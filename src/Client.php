<?php

namespace Lineage;

use Exception;
use Lineage\DTO\DecryptedWalletDTO;
use Lineage\DTO\EncryptedKeypairDTO;
use Lineage\DTO\EncryptedWalletDTO;
use Lineage\DTO\PaymentAssetDTO;
use Lineage\Exceptions\ActiveWalletNotSetException;
use Lineage\Exceptions\NotImplemented;
use Lineage\Exceptions\PassPhraseNotSetException;
use Lineage\Functions\KeyHelpers;
use Lineage\Functions\TxBuilder;
use Lineage\Serialization;
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
     * Seed Phrase, which is to be stored securely by the owner of this wallet.
     *
     * Every keypair this SDK derives comes straight from the mnemonic
     * (KeyHelpers::getNewKeypair/deriveKeypair), so — unlike the legacy
     * PBKDF2-derived "master key" this used to seal — the wire/on-disk
     * representation here seals the mnemonic itself under the wallet
     * passphrase (KeyHelpers::encryptMnemonic), matching sdk-go's
     * Wallet.InitNew/FromSeed.
     *
     * @return EncryptedWalletDTO
     */
    public function createWallet(?string $seedPhrase = null): EncryptedWalletDTO
    {
        $mnemonic = $seedPhrase ?? KeyHelpers::generateSeed();

        $encrypted = KeyHelpers::encryptMnemonic($mnemonic, $this->getPassPhrase());

        return new EncryptedWalletDTO(
            masterKeyEncrypted: $encrypted['save'],
            nonce: $encrypted['nonce'],
            seedPhrase: $mnemonic
        );
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
        $mnemonic = KeyHelpers::decryptMnemonic(
            save: $wallet->getMasterKeyEncrypted(),
            nonce: $wallet->getNonce(),
            passphraseKey: $this->getPassPhrase()
        );

        $this->walletDecrypted = new DecryptedWalletDTO(mnemonic: $mnemonic);

        return true;
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
            mnemonic: $this->walletDecrypted->getMnemonic(),
            passphraseKey: $this->getPassPhrase(),
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
     * Creates an item asset at the address associated with $keypair, signing
     * the item-asset signable hash with its decrypted secret key, and
     * submits `POST /v1/items`. $defaultGenesisHash selects between the
     * well-known default item DRS transaction hash (true) and a freshly
     * assigned one (false). Mirrors sdk-go's Wallet.CreateItems / sdk-js's
     * Wallet.createItems.
     *
     * Field order matters: it is built to be byte-identical to sdk-js's wire
     * body (item.json's vector `payload`, minus the legacy `version` field
     * sdk-js's request interface omits) — the server is serde/order
     * independent, but this keeps the request comparable byte-for-byte
     * against the golden vector.
     *
     * @return array
     */
    public function createItems(
        EncryptedKeypairDTO $keypair,
        bool $defaultGenesisHash = true,
        int $amount = 1000,
        ?string $metadata = null,
    ): array {
        $decrypted = $this->decryptKeypair($keypair->getContent(), $keypair->getNonce());

        $genesisHashSpec = $defaultGenesisHash ? 'Default' : 'Create';

        // The genesis hash isn't part of the item-asset signable hash (it
        // isn't known until the server assigns/resolves it) — matches
        // sdk-js's createItemPayload / sdk-go's CreateItems.
        $asset = Serialization::assetItem($amount, '', $metadata);
        $signableHash = KeyHelpers::constructItemAssetSignableHash($asset);
        $signature = KeyHelpers::constructSignature($signableHash, $decrypted['secretKey']);

        $scriptPublicKey = KeyHelpers::constructAddress($decrypted['publicKey']);
        $publicKeyHex = sodium_bin2hex($decrypted['publicKey']);

        return $this->request(
            method: self::POST,
            host: $this->mempoolHost,
            path: '/v1/items',
            body: [
                'item_amount' => $amount,
                'script_public_key' => $scriptPublicKey,
                'public_key' => $publicKeyHex,
                'signature' => $signature,
                'genesis_hash_spec' => $genesisHashSpec,
                'metadata' => $metadata,
            ],
        );
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

    /**
     * Sends $amount Token assets to $paymentAddress, sourcing inputs from
     * $allKeypairs's addresses and sending change to $excessKeypair's
     * address. Mirrors sdk-go's Wallet.MakeTokenPayment / sdk-js's
     * Wallet.makeTokenPayment.
     *
     * @param array<EncryptedKeypairDTO> $allKeypairs
     *
     * @return array
     */
    public function makeTokenPayment(
        string $paymentAddress,
        int $amount,
        array $allKeypairs,
        EncryptedKeypairDTO $excessKeypair,
        int $locktime = 0,
    ): array {
        return $this->makePayment(
            $paymentAddress,
            Serialization::assetToken($amount),
            $allKeypairs,
            $excessKeypair,
            $locktime
        );
    }

    /**
     * Sends $amount Item assets (of the given $genesisHash) to
     * $paymentAddress, sourcing inputs from $allKeypairs's addresses and
     * sending change to $excessKeypair's address. Mirrors sdk-go's
     * Wallet.MakeItemPayment / sdk-js's Wallet.makeItemPayment.
     *
     * @param array<EncryptedKeypairDTO> $allKeypairs
     *
     * @return array
     */
    public function makeItemPayment(
        string $paymentAddress,
        int $amount,
        string $genesisHash,
        array $allKeypairs,
        EncryptedKeypairDTO $excessKeypair,
        ?string $metadata = null,
        int $locktime = 0,
    ): array {
        return $this->makePayment(
            $paymentAddress,
            Serialization::assetItem($amount, $genesisHash, $metadata),
            $allKeypairs,
            $excessKeypair,
            $locktime
        );
    }

    /**
     * Shared implementation behind makeTokenPayment/makeItemPayment: decrypt
     * $allKeypairs, fetch their combined balance, build the payment
     * transaction via TxBuilder::createPaymentTx, and submit it via
     * `POST /v1/transactions`. Mirrors sdk-go's private Wallet.makePayment /
     * sdk-js's private Wallet.makePayment.
     *
     * The submitted body is `{"transactions":[{...createTx,"fees":null}]}`
     * — `fees` isn't part of the signed transaction, it's a separate,
     * always-null field the /v1 DTO requires, appended last (matching
     * sdk-js's `{...tx, fees: null}` spread).
     *
     * @param array $asset A Serialization asset array (Serialization::assetToken/assetItem).
     * @param array<EncryptedKeypairDTO> $allKeypairs
     */
    private function makePayment(
        string $paymentAddress,
        array $asset,
        array $allKeypairs,
        EncryptedKeypairDTO $excessKeypair,
        int $locktime,
    ): array {
        if (count($allKeypairs) === 0) {
            throw new \RuntimeException('makePayment: no keypairs provided');
        }

        $addresses = [];
        $keyPairs = [];

        foreach ($allKeypairs as $encrypted) {
            $decrypted = $this->decryptKeypair($encrypted->getContent(), $encrypted->getNonce());
            $addresses[] = $encrypted->getAddress();
            $keyPairs[$encrypted->getAddress()] = $decrypted;
        }

        $balance = $this->fetchBalance($addresses);

        $tx = TxBuilder::createPaymentTx(
            $paymentAddress,
            $asset,
            $excessKeypair->getAddress(),
            $balance,
            $keyPairs,
            $locktime
        );

        return $this->request(
            method: self::POST,
            host: $this->mempoolHost,
            path: '/v1/transactions',
            body: [
                'transactions' => [
                    [
                        'inputs' => $tx['inputs'],
                        'outputs' => $tx['outputs'],
                        'version' => $tx['version'],
                        'druid_info' => $tx['druid_info'],
                        'fees' => null,
                    ],
                ],
            ],
        );
    }

    /**
     * 2-way payments (trade requests) are deferred until the /v1 endpoints
     * for them land.
     *
     * @return never
     */
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
        throw new NotImplemented();
    }

    /**
     * 2-way payments (trade requests) are deferred until the /v1 endpoints
     * for them land.
     *
     * @return never
     */
    public function getPendingTransactions(
        array $keypairs,
        ?array $encryptedTransactionMap = []
    ): array {
        throw new NotImplemented();
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

    /**
     * 2-way payments (trade requests) are deferred until the /v1 endpoints
     * for them land.
     *
     * @return never
     */
    private function respondToPendingTransaction(
        string $status,
        string $druid,
        array $keypairs,
    ): array {
        throw new NotImplemented();
    }

    private function decryptKeypair(string $encryptedKey, string $nonce): array
    {
        try {
            return KeyHelpers::decryptKeypair(
                save: $encryptedKey,
                nonce: $nonce,
                passphraseKey: $this->getPassPhrase()
            );
        } catch (Exception $e) {
            throw($e);
        }
    }
}
