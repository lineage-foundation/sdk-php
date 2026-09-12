<?php

namespace Lineage;

use Exception;
use Lineage\DTO\DecryptedWalletDTO;
use Lineage\DTO\DruidInfoDTO;
use Lineage\DTO\EncryptedKeypairDTO;
use Lineage\DTO\EncryptedWalletDTO;
use Lineage\DTO\PaymentAssetDTO;
use Lineage\DTO\PaymentExpectationDTO;
use Lineage\DTO\TransactionDTO;
use Lineage\DTO\TransactionOutputDTO;
use Lineage\Exceptions\ActiveWalletNotSetException;
use Lineage\Exceptions\PassPhraseNotSetException;
use Lineage\Functions\IntercomUtils;
use Lineage\Functions\KeyHelpers;
use Lineage\Traits\MakesRequests;

class Client
{
    use MakesRequests;

    final public const TRANSACTION_STATUS_PENDING = 'pending';
    final public const TRANSACTION_STATUS_ACCEPTED = 'accepted';
    final public const TRANSACTION_STATUS_REJECTED = 'rejected';

    private ?string $passPhraseHash = null;

    private ?DecryptedWalletDTO $walletDecrypted = null;

    public function __construct(
        private string $mempoolHost,
        private string $storageHost,
        private ?string $apiKey = null,
    ) {
    }

    /**
     * Set the pass phrase for the wallet to be created or opened.
     *
     * @param string $passPhrase
     *
     * @return void
     */
    public function setPassPhrase(string $passPhrase): void
    {
        $this->passPhraseHash = KeyHelpers::getPassPhraseHash($passPhrase);
    }

    /**
     * Return the hashed passphrase set earlier.
     *
     * @return string
     */
    private function getPassPhrase(): string
    {
        if (!$this->passPhraseHash) {
            throw new PassPhraseNotSetException();
        }

        return $this->passPhraseHash;
    }

    /**
     * Creates and returns an encrypted Lineage wallet. The return value includes the 12-word mnemonic
     * Seed Phrase, which is to be stored securely by the owner of this wallet
     *
     * @return EncryptedWalletDTO
     */
    public function createWallet(?string $seedPhrase = null): EncryptedWalletDTO
    {
        $walletArr = KeyHelpers::initialiseFromPassphrase($this->getPassPhrase(), $seedPhrase);

        $walletDTO = new EncryptedWalletDTO(
            masterKeyEncrypted: $walletArr['masterKeyEncrypted'],
            nonce: $walletArr['nonce'],
            seedPhrase: $walletArr['seedPhrase']
        );

        return $walletDTO;
    }

    /**
     * Opens (decrypts) an existing wallet and returns true or false depending on if it was
     * successful.
     *
     * @param EncryptedWalletDTO $wallet
     *
     * @return boolean
     */
    public function openWallet(EncryptedWalletDTO $wallet): bool
    {
        try {
            $masterKeyDecrypted = $this->decryptKeypair(
                encryptedKey: $wallet->getMasterKeyEncrypted(),
                nonce: $wallet->getNonce()
            );

            $this->walletDecrypted = new DecryptedWalletDTO(
                masterPrivateKey: $masterKeyDecrypted['publicKey'],
                chainCode: $masterKeyDecrypted['secretKey']
            );

            return true;
        } catch (\Exception $e) {
            throw $e;
        }
    }

    /**
     * Creates and returns an encrypted keypair and associated address,
     * using the decrypted wallet and supplied pass phrase
     *
     * @return array
     */
    public function createKeypair(array $existingAddresses = []): EncryptedKeypairDTO
    {
        if (!$this->walletDecrypted) {
            throw new ActiveWalletNotSetException();
        }

        $keypairArr = KeyHelpers::getNewKeypair(
            masterPrivateKey: $this->walletDecrypted->getMasterPrivateKey(),
            passPhrase: $this->getPassPhrase(),
            existingAddresses: $existingAddresses
        );

        return new EncryptedKeypairDTO(
            address: $keypairArr['address'],
            nonce: $keypairArr['nonce'],
            content: $keypairArr['save']
        );
    }

    /**
     * Gets a single stored blockchain entry (a block or a transaction) by its
     * raw storage key. Hits the storage host: GET /v1/blockchain-entries/{key}.
     *
     * @param string $key
     *
     * @return array
     */
    public function getBlockchainEntry(string $key): array
    {
        return $this->request(
            method: self::GET,
            host: $this->storageHost,
            path: '/v1/blockchain-entries/' . rawurlencode($key),
        );
    }

    /**
     * Batch-looks-up UTXO balances for the given addresses. Hits the mempool
     * host: POST /v1/balances/query. Returns the `balance` breakdown (total
     * asset amounts and per-address outpoints).
     *
     * @param array $addrs
     *
     * @return array
     */
    public function fetchBalance(array $addrs): array
    {
        $response = $this->request(
            method: self::POST,
            host: $this->mempoolHost,
            path: '/v1/balances/query',
            body: ['addresses' => $addrs],
        );

        return $response['balance'] ?? [];
    }

    /**
     * Gets the total and currently issued token supply. Hits the mempool
     * host: GET /v1/supply.
     *
     * @return array
     */
    public function getSupply(): array
    {
        return $this->request(
            method: self::GET,
            host: $this->mempoolHost,
            path: '/v1/supply',
        );
    }

    /**
     * Gets a single stored block by number. Hits the storage host:
     * GET /v1/blocks/{num}.
     *
     * @param int $num
     *
     * @return array
     */
    public function getBlock(int $num): array
    {
        return $this->request(
            method: self::GET,
            host: $this->storageHost,
            path: '/v1/blocks/' . $num,
        );
    }

    /**
     * Gets the most recently stored block. Hits the storage host:
     * GET /v1/blocks/latest.
     *
     * @return array
     */
    public function getLatestBlock(): array
    {
        return $this->request(
            method: self::GET,
            host: $this->storageHost,
            path: '/v1/blocks/latest',
        );
    }

    /**
     * Batch-looks-up mempool status for the given transaction hashes. Hits
     * the mempool host: POST /v1/transactions/status:query.
     *
     * @param array $hashes
     *
     * @return array
     */
    public function getTransactionStatus(array $hashes): array
    {
        return $this->request(
            method: self::POST,
            host: $this->mempoolHost,
            path: '/v1/transactions/status:query',
            body: ['hashes' => $hashes],
        );
    }

    /**
     * Creates an item asset at the address associated with the encrypted keypair. Returns the item.
     *
     * @param string     $name         - this is the name that will be merged in with supplied meta data (if any)
     * @param string     $encryptedKey - the encrypted keypair
     * @param string     $nonce        - the nonce as returned by the keypair creation
     * @param integer    $amount       - how many of these are we making
     * @param boolean    $defaultHash  - if false, a generic item is created. If not, a hash that identifies this item will be generated
     * @param array|null $metaData     - an optional key-value array of extra info
     *
     * @return array
     */
    public function createAsset(
        string $name,
        string $encryptedKey,
        string $nonce,
        int $amount,
        bool $defaultHash,
        ?array $metaData = [],
    ): PaymentAssetDTO {
        // The legacy compute-node asset-creation path is gone under /v1.
        // Re-implemented against POST /v1/transactions:create in Task 10.
        throw new \RuntimeException('migrating to /v1 — see Task 10');
    }

    public function sendAssetToAddress(
        array $senderKeypairs,
        string $address,
        PaymentAssetDTO $asset,
        ?string $excessAddress = null,
    ): array {
        // The legacy compute-node payment path is gone under /v1.
        // Re-implemented against POST /v1/transactions:create in Task 10.
        throw new \RuntimeException('migrating to /v1 — see Task 10');
    }

    public function getPaymentAssetObject(
        int $amount,
        ?string $hash,
        ?array $metaData = null
    ): PaymentAssetDTO {
        return new PaymentAssetDTO(
            amount: $amount,
            drsTxHash: $hash,
            metaData: $metaData
        );
    }

    public function createTradeRequest(
        // the other party's address to send $myAsset to
        string $otherPartyAddress,
        PaymentAssetDTO $myAsset,

        // my address to get some $otherPartyAsset back into
        string $myAddress,
        PaymentAssetDTO $otherPartyAsset,

        // where to collect $myAsset from
        array $myKeypairs,
    ): array {
        // The legacy intercom-based trade-request path is gone under /v1.
        // Re-implemented against the /v1 transaction endpoints in Task 10.
        throw new \RuntimeException('migrating to /v1 — see Task 10');
    }

    private function makePaymentPayload(
        array $myKeypairs,
        PaymentAssetDTO $myAsset,
        string $otherPartyAddress,
        ?string $excessAddress = null,
        ?DruidInfoDTO $druidInfo = null
    ): array {
        // Re-implemented against the /v1 transaction endpoints in Task 10.
        throw new \RuntimeException('migrating to /v1 — see Task 10');
    }

    //Not sure I agree with this - accepted transactions are processed in this function, as per the JS lib
    public function getPendingTransactions(
        array $keypairs,
        ?array $encryptedTransactionMap = []
    ): array {
        // The legacy intercom get/accept/reject-data path is gone under /v1.
        // Re-implemented against the /v1 transaction endpoints in Task 10.
        throw new \RuntimeException('migrating to /v1 — see Task 10');
    }

    public function acceptPendingTransaction(
        string $druid,
        array $keypairs,
    ): array {
        return $this->respondToPendingTransaction(
            status: self::TRANSACTION_STATUS_ACCEPTED,
            druid: $druid,
            keypairs: $keypairs
        );
    }

    public function rejectPendingTransaction(
        string $druid,
        array $keypairs,
    ): array {
        return $this->respondToPendingTransaction(
            status: self::TRANSACTION_STATUS_REJECTED,
            druid: $druid,
            keypairs: $keypairs
        );
    }

    private function getAmountAndHashFromExpectation(array $expectation): array
    {
        return array_keys($expectation['asset'])[0] === PaymentAssetDTO::ASSET_TYPE_ITEM ? [
            'amount' => $expectation['asset'][PaymentAssetDTO::ASSET_TYPE_ITEM]['amount'],
            'hash' => $expectation['asset'][PaymentAssetDTO::ASSET_TYPE_ITEM]['drs_tx_hash']
        ] : [
            'amount' => $expectation['asset'][PaymentAssetDTO::ASSET_TYPE_TOKEN],
            'hash' => null
        ];
    }

    private function respondToPendingTransaction(
        string $status,
        string $druid,
        array $keypairs,
    ): array {
        // The legacy intercom accept/reject path is gone under /v1.
        // Re-implemented against the /v1 transaction endpoints in Task 10.
        throw new \RuntimeException('migrating to /v1 — see Task 10');
    }

    private function getInputsForTransaction(
        array $myKeypairs,
        array $myBalance,
        PaymentAssetDTO $myAsset
    ): array {
        $totalAmountGathered = 0;
        $usedAddresses = [];
        $depletedAddresses = [];
        $addressVersion = null;
        $inputs = [];

        foreach ($myBalance['address_list'] as $address => $outPoints) {
            $usedOutpointsCount = 0;
            $keypair = $myKeypairs[$address];
            $keypairDecrypted = $this->getDecryptedKeypair(address: $address, keypair: $keypair);

            $outPointIndex = -1;

            while($totalAmountGathered < $myAsset->getAmount() && $outPointIndex < count($outPoints)) {
                $outPointIndex++;
                $outPointArr = $outPoints[$outPointIndex];

                // This outpoint doesn't have what we want
                if(!isset($outPointArr['value'][$myAsset->getAssetType()]) ||
                    ($myAsset->getAssetType() === PaymentAssetDTO::ASSET_TYPE_ITEM &&
                    $outPointArr['value'][$myAsset->getAssetType()]['drs_tx_hash'] !== $myAsset->getDrsTxHash())) {
                    continue;
                }

                $signableData = $this->getSignableAssetHash($outPointArr['out_point']);

                $signature = KeyHelpers::createSignature($signableData, $keypairDecrypted['secretKey']);

                array_push($inputs, [
                    'script_signature' => ['Pay2PkH' => [
                        'signable_data'   => $signableData ?? '',
                        'signature'       => $signature,
                        'public_key'      => sodium_bin2hex($keypairDecrypted['publicKey']),
                        'address_version' => $addressVersion,
                    ]],
                    'previous_out' => $outPointArr['out_point'],
                ]);

                $totalAmountGathered += $myAsset->getAssetType() === PaymentAssetDTO::ASSET_TYPE_ITEM ? $outPointArr['value'][$myAsset->getAssetType()]['amount'] :
                    $outPointArr['value'][$myAsset->getAssetType()];

                if (! in_array($address, $usedAddresses)) {
                    array_push($usedAddresses, $address);
                }

                $usedOutpointsCount++;

                if (count($outPoints) == $usedOutpointsCount) {
                    array_push($depletedAddresses, $address);
                }
            }
        }

        return [
            'depletedAddresses'   => $depletedAddresses,
            'inputs'              => $inputs,
            'totalAmountGathered' => $totalAmountGathered,
            'usedAddresses'       => $usedAddresses,
        ];
    }

    private function doTransaction(
        array $payload,
        ?string $host = null
    ): array {
        // Re-implemented against POST /v1/transactions:create in Task 10.
        throw new \RuntimeException('migrating to /v1 — see Task 10');
    }

    private function getDecryptedKeypair($address, $keypair): array
    {
        return [
            'address' => $address,
            'version' => null,
            ...$this->decryptKeypair(
                encryptedKey: $keypair['encryptedKey'],
                nonce: $keypair['nonce']
            ),
        ];
    }

    private function decryptKeypair(string $encryptedKey, string $nonce): array
    {
        try {
            return KeyHelpers::decryptKeypair(
                encryptedKey: $encryptedKey,
                nonce: $nonce,
                passPhrase: $this->getPassPhrase()
            );
        } catch (Exception $e) {
            throw($e);
        }
    }

    private function getSignableAssetHash(array $asset): string
    {
        if (isset($asset['n']) && isset($asset['t_hash'])) {
            return hash('sha3-256', KeyHelpers::getFormattedOutPointString($asset));
        }

        if (isset($asset['token'])) {
            return hash('sha3-256', ("Token:{$asset['amount']}"));
        }

        if (isset($asset['amount'])) {
            return hash('sha3-256', ("Item:{$asset['amount']}"));
        }

        return '';
    }
}
