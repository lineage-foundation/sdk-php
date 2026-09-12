<?php

namespace Lineage\Functions;

use Lineage\Serialization;

/**
 * TxBuilder assembles /v1 transactions the same way sdk-js's tx.mgmt.ts
 * does. createPaymentTx replicates createPaymentTx/getInputsForTx/
 * createTx/updateSignatures: inputs are selected from a fetched balance (in
 * the order addresses/out-points appear in $balance['address_list'],
 * matching sdk-js's Object.entries iteration over the decoded JSON — the
 * server's address_list is a BTreeMap, so real API responses are already
 * address-sorted), outputs are [payment, change] (change only when there is
 * excess), then every input is (re)signed over the signable hash of its
 * previous-out plus the full output set. This must stay byte-identical to
 * sdk-js/sdk-go since the mempool verifies signatures over the same
 * JSON-encoded preimage the client signed.
 */
class TxBuilder
{
    private const NETWORK_VERSION = 2;

    /**
     * Build a payment transaction sending $asset to $paymentAddress,
     * sourcing inputs from $balance and sending any change to
     * $excessAddress. Returns the /v1/transactions createTx struct:
     * {inputs, outputs, version, druid_info}.
     *
     * @param array $asset A Serialization asset array: ['Token'=>n] or
     *   ['Item'=>['amount'=>..,'genesis_hash'=>..,'metadata'=>..]].
     * @param array $balance The FetchBalance response shape:
     *   {total:{tokens,items},address_list:{address:[{out_point,value},...]}}.
     * @param array $keyPairs address => decrypted keypair
     *   (['publicKey'=>raw bytes,'secretKey'=>raw bytes]).
     */
    public static function createPaymentTx(
        string $paymentAddress,
        array $asset,
        string $excessAddress,
        array $balance,
        array $keyPairs,
        int $locktime
    ): array {
        return self::createTxWithDruidInfo($paymentAddress, $asset, $excessAddress, $balance, $keyPairs, $locktime, null);
    }

    /**
     * Build one half of a two-way (DRUID) trade: an ordinary P2PKH
     * transaction that pays $counterExpectation['asset'] to
     * $counterExpectation['to'] (plus any excess back to $excessAddress),
     * carrying $thisExpectation as this party's half of the DRUID trade
     * metadata.
     *
     * This replicates sdk-js's create2WTxHalf byte-for-byte: input
     * selection and output/signature construction are exactly
     * createPaymentTx's (driven by $counterExpectation's asset/to), and
     * druid_info is attached as {druid, participants: 2,
     * expectations: [$thisExpectation]} — UNSIGNED, and never folded into
     * any signable preimage. Each input is signed exactly as in the 1-way
     * path, over KeyHelpers::constructTxInOutSignableHash(previous_out,
     * outputs).
     *
     * @param array $thisExpectation ['from'=>..,'to'=>..,'asset'=>..] — this
     *   party's half of the trade, recorded in druid_info.
     * @param array $counterExpectation ['from'=>..,'to'=>..,'asset'=>..] —
     *   the counterparty's half; its asset/to drive the outputs of this
     *   half exactly like createPaymentTx's $asset/$paymentAddress.
     */
    public static function create2WTxHalf(
        string $druid,
        array $thisExpectation,
        array $counterExpectation,
        array $balance,
        array $keyPairs,
        string $excessAddress,
        int $locktime
    ): array {
        $druidInfo = Serialization::druidInfo($druid, 2, [
            Serialization::druidExpectation(
                $thisExpectation['from'],
                $thisExpectation['to'],
                $thisExpectation['asset']
            ),
        ]);

        return self::createTxWithDruidInfo(
            $counterExpectation['to'],
            $counterExpectation['asset'],
            $excessAddress,
            $balance,
            $keyPairs,
            $locktime,
            $druidInfo
        );
    }

    /**
     * The shared core of createPaymentTx and create2WTxHalf: gather inputs
     * for $asset, build [payment, change] outputs, sign every input over
     * the full output set, and stamp $druidInfo (null for an ordinary
     * 1-way payment) onto the result.
     */
    private static function createTxWithDruidInfo(
        string $paymentAddress,
        array $asset,
        string $excessAddress,
        array $balance,
        array $keyPairs,
        int $locktime,
        ?array $druidInfo
    ): array {
        [$inputs, $totalGathered] = self::getInputsForTx($asset, $balance, $keyPairs);

        if (count($inputs) === 0) {
            throw new \RuntimeException('TxBuilder: no inputs available to cover payment');
        }

        $outputs = [
            Serialization::txOut($asset, $locktime, $paymentAddress),
        ];

        if (self::assetAmount($totalGathered) > self::assetAmount($asset)) {
            $outputs[] = Serialization::txOut(
                self::subAsset($totalGathered, $asset),
                0,
                $excessAddress
            );
        }

        $tx = [
            'inputs' => $inputs,
            'outputs' => $outputs,
            'version' => self::NETWORK_VERSION,
            'druid_info' => $druidInfo,
        ];

        return self::updateSignatures($tx, $balance, $keyPairs);
    }

    /**
     * Select unspent outputs from $balance to cover $asset, walking
     * addresses/out-points in the order they appear in
     * $balance['address_list']. Returns [inputs, totalGathered].
     */
    private static function getInputsForTx(array $asset, array $balance, array $keyPairs): array
    {
        if (!self::hasEnoughFunds($asset, $balance)) {
            throw new \RuntimeException('TxBuilder: insufficient funds');
        }

        $total = self::zeroAssetLike($asset);
        $inputs = [];

        foreach ($balance['address_list'] as $address => $outPoints) {
            if (!isset($keyPairs[$address])) {
                throw new \RuntimeException("TxBuilder: no keypair for address \"{$address}\"");
            }
            $keyPair = $keyPairs[$address];
            $addressVersion = self::addressVersionForKeypair($keyPair['publicKey'], $address);

            foreach ($outPoints as $entry) {
                if (self::assetAmount($total) >= self::assetAmount($asset)) {
                    continue;
                }
                if (!self::assetsCompatible($asset, $entry['value'])) {
                    continue;
                }

                $inputs[] = [
                    'previous_out' => $entry['out_point'],
                    'script_signature' => [
                        'Pay2PkH' => [
                            'signable_data' => '',
                            'signature' => '',
                            'public_key' => bin2hex($keyPair['publicKey']),
                            'address_version' => $addressVersion,
                        ],
                    ],
                ];

                $total = self::addAsset($total, $entry['value']);
            }
        }

        return [$inputs, $total];
    }

    /**
     * Re-sign every input now that the full output set is known, matching
     * sdk-js's updateSignatures: each input's signable_data/signature is
     * (re)computed over KeyHelpers::constructTxInOutSignableHash
     * (previous_out, outputs).
     */
    private static function updateSignatures(array $tx, array $balance, array $keyPairs): array
    {
        foreach ($tx['inputs'] as &$input) {
            $address = self::addressForOutPoint($balance, $input['previous_out']['t_hash']);
            $keyPair = $keyPairs[$address];

            $signableData = KeyHelpers::constructTxInOutSignableHash($input['previous_out'], $tx['outputs']);
            $signature = KeyHelpers::constructSignature($signableData, $keyPair['secretKey']);

            $input['script_signature']['Pay2PkH']['signable_data'] = $signableData;
            $input['script_signature']['Pay2PkH']['signature'] = $signature;
        }
        unset($input);

        return $tx;
    }

    /**
     * Find the address in $balance['address_list'] that owns the out-point
     * identified by $tHash, matching sdk-js's
     * getAddressFromFetchBalanceResponse.
     */
    private static function addressForOutPoint(array $balance, string $tHash): string
    {
        foreach ($balance['address_list'] as $address => $outPoints) {
            foreach ($outPoints as $entry) {
                if ($entry['out_point']['t_hash'] === $tHash) {
                    return $address;
                }
            }
        }

        throw new \RuntimeException("TxBuilder: no address in balance owns out-point \"{$tHash}\"");
    }

    /**
     * The address_version to record for an input's script signature: null
     * for the current/default address derivation (hex(sha3_256(publicKey))).
     * Old/temporary address versions are not supported by this builder.
     */
    private static function addressVersionForKeypair(string $publicKey, string $address): ?int
    {
        if (KeyHelpers::constructAddress($publicKey) === $address) {
            return null;
        }

        throw new \RuntimeException(
            "TxBuilder: address \"{$address}\" does not match the default derivation for its public key "
            . '(old/temp address versions are not supported)'
        );
    }

    private static function hasEnoughFunds(array $asset, array $balance): bool
    {
        if (isset($asset['Token'])) {
            return $asset['Token'] <= $balance['total']['tokens'];
        }

        $genesisHash = $asset['Item']['genesis_hash'];

        return $asset['Item']['amount'] <= ($balance['total']['items'][$genesisHash] ?? 0);
    }

    /**
     * Two assets can be combined/compared if they're the same kind, and
     * (for Item assets) additionally share a genesis hash.
     */
    private static function assetsCompatible(array $a, array $b): bool
    {
        if (isset($a['Token']) !== isset($b['Token'])) {
            return false;
        }

        if (isset($a['Item'])) {
            return $a['Item']['genesis_hash'] === $b['Item']['genesis_hash'];
        }

        return true;
    }

    private static function assetAmount(array $asset): int
    {
        return $asset['Token'] ?? $asset['Item']['amount'];
    }

    private static function zeroAssetLike(array $asset): array
    {
        if (isset($asset['Token'])) {
            return Serialization::assetToken(0);
        }

        return Serialization::assetItem(0, $asset['Item']['genesis_hash'], $asset['Item']['metadata'] ?? null);
    }

    private static function addAsset(array $a, array $b): array
    {
        if (isset($a['Token'])) {
            return Serialization::assetToken($a['Token'] + $b['Token']);
        }

        return Serialization::assetItem(
            $a['Item']['amount'] + $b['Item']['amount'],
            $a['Item']['genesis_hash'],
            $a['Item']['metadata']
        );
    }

    private static function subAsset(array $a, array $b): array
    {
        if (isset($a['Token'])) {
            return Serialization::assetToken($a['Token'] - $b['Token']);
        }

        return Serialization::assetItem(
            $a['Item']['amount'] - $b['Item']['amount'],
            $a['Item']['genesis_hash'],
            $a['Item']['metadata']
        );
    }
}
