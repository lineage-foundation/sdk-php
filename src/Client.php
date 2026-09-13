<?php

namespace Lineage;

use Exception;
use Lineage\DTO\DecryptedWalletDTO;
use Lineage\DTO\EncryptedKeypairDTO;
use Lineage\DTO\EncryptedWalletDTO;
use Lineage\DTO\PaymentAssetDTO;
use Lineage\Exceptions\ActiveWalletNotSetException;
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

    private ?ValenceClient $valenceClient = null;

    public function __construct(
        private string $mempoolHost,
        private string $storageHost,
        private ?string $apiKey = null,
        private ?string $valenceHost = null,
    ) {
    }

    /**
     * Inject a ValenceClient (e.g. one built on top of a mock Guzzle stack)
     * in place of the lazily-created default. Intended for tests.
     */
    public function setValenceClient(ValenceClient $valenceClient): void
    {
        $this->valenceClient = $valenceClient;
    }

    /**
     * The valence mailbox client used by the 2-way payment flow methods,
     * lazily built against $valenceHost and this Client's own (possibly
     * test-injected) Guzzle client.
     */
    private function getValenceClient(): ValenceClient
    {
        if ($this->valenceClient === null) {
            if (!$this->valenceHost) {
                throw new \RuntimeException('Client: valence host not configured');
            }

            $this->valenceClient = new ValenceClient($this->valenceHost, $this->getHttpClient());
        }

        return $this->valenceClient;
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
     * Offers a two-way (DRUID) trade to $paymentAddress: this wallet will
     * pay $sendingAsset to $paymentAddress in exchange for $receivingAsset
     * delivered to $receiveKeypair's address. Builds this party's
     * transaction half (sourcing inputs from $allKeypairs's addresses,
     * change back to $receiveKeypair's address), posts the plaintext offer
     * to valence (addressed to $paymentAddress's mailbox, signed by
     * $receiveKeypair), and returns a pending half — this party's half,
     * encrypted at rest under the wallet's passphrase — for the caller to
     * persist until fetchPending2WayPayment reports it settled. Mirrors
     * sdk-go's Wallet.Make2WayPayment / sdk-js's Wallet.make2WayPayment.
     *
     * @param array $sendingAsset A Serialization asset array (Serialization::assetToken/assetItem).
     * @param array $receivingAsset A Serialization asset array (Serialization::assetToken/assetItem).
     * @param array<EncryptedKeypairDTO> $allKeypairs
     *
     * @return array{druid:string,encryptedHalf:array,senderExpectation:array,receiverExpectation:array}
     */
    public function make2WayPayment(
        string $paymentAddress,
        array $sendingAsset,
        array $receivingAsset,
        array $allKeypairs,
        EncryptedKeypairDTO $receiveKeypair,
    ): array {
        if (count($allKeypairs) === 0) {
            throw new \RuntimeException('make2WayPayment: no keypairs provided');
        }

        [$addresses, $keyPairs] = $this->decryptKeypairsMap($allKeypairs);

        $senderKeyPair = $this->decryptKeypair($receiveKeypair->getContent(), $receiveKeypair->getNonce());

        $balance = $this->fetchBalance($addresses);

        $druid = KeyHelpers::generateDRUID();

        // senderExpectation: what this (sending) party expects to receive.
        // receiverExpectation: what the counterparty (payee) is owed by this half.
        $senderExpectation = Serialization::druidExpectation('', $receiveKeypair->getAddress(), $receivingAsset);
        $receiverExpectation = Serialization::druidExpectation('', $paymentAddress, $sendingAsset);

        $myHalf = TxBuilder::create2WTxHalf(
            $druid,
            $senderExpectation,
            $receiverExpectation,
            $balance,
            $keyPairs,
            $receiveKeypair->getAddress(),
            0
        );

        // Now that this half's inputs are known, fill in the "from" the
        // counterparty will use to correlate their acceptance transaction.
        $receiverExpectation['from'] = KeyHelpers::constructTxInsAddress($myHalf['inputs']);

        $encryptedHalf = KeyHelpers::encryptTransaction($myHalf, $this->getPassPhrase());

        $details = [
            'druid' => $druid,
            'senderExpectation' => $senderExpectation,
            'receiverExpectation' => $receiverExpectation,
            'status' => self::TRANSACTION_STATUS_PENDING,
            'mempoolHost' => $this->mempoolHost,
        ];

        $this->getValenceClient()->post($paymentAddress, $senderKeyPair, $details);

        return [
            'druid' => $druid,
            'encryptedHalf' => $encryptedHalf,
            'senderExpectation' => $senderExpectation,
            'receiverExpectation' => $receiverExpectation,
        ];
    }

    /**
     * Polls this wallet's own mailboxes — one per address in $allKeypairs,
     * deduplicated — and does both of this wallet's possible roles in a
     * two-way (DRUID) trade against whatever it finds there:
     *
     *  1. Acceptor discovery: an offer make2WayPayment posts is addressed
     *     to whichever of the counterparty's own addresses it was handed as
     *     paymentAddress, so it lands in one of *our* mailboxes here. Any
     *     mailbox entry whose druid isn't in $storedPendingHalves — this
     *     wallet never initiated it — is surfaced as-is in the returned
     *     'pending' map for the caller to inspect and
     *     accept2WayPayment/reject2WayPayment.
     *  2. Initiator settlement: an offer this wallet made shows up back in
     *     its own mailbox once the counterparty accepts. For any such entry
     *     — druid present in $storedPendingHalves, status "accepted" — the
     *     stored half is decrypted, its druid_info expectation is replaced
     *     with the counterparty-filled senderExpectation now on the mailbox
     *     entry, the resulting transaction is submitted to this wallet's
     *     own mempool, and the settled mailbox entry is deleted.
     *
     * A failure against one mailbox, or one mailbox entry, never discards
     * progress already made against the others: 'pending' and 'settled' are
     * accumulated across every mailbox regardless of errors elsewhere, and
     * are always returned rather than the call throwing. Every error
     * encountered along the way is instead collected into the returned
     * 'errors' list, mirroring sdk-go's Wallet.FetchPending2WayPayment
     * (which joins them via errors.Join into its returned err) so a caller
     * can still observe partial failures.
     *
     * @param array $storedPendingHalves The caller-persisted return values of prior make2WayPayment calls.
     * @param array<EncryptedKeypairDTO> $allKeypairs
     *
     * @return array{pending:array<string,array>,settled:array<int,string>,errors:array<int,string>}
     */
    public function fetchPending2WayPayment(array $storedPendingHalves, array $allKeypairs): array
    {
        [$addresses, $keyPairs] = $this->decryptKeypairsMap($allKeypairs);

        $storedByDruid = [];
        foreach ($storedPendingHalves as $half) {
            $storedByDruid[$half['druid']] = $half;
        }

        $pending = [];
        $settled = [];
        $errors = [];
        $valenceClient = $this->getValenceClient();

        $seenMailbox = [];
        foreach ($addresses as $mailboxAddress) {
            if (isset($seenMailbox[$mailboxAddress])) {
                continue;
            }
            $seenMailbox[$mailboxAddress] = true;

            $keyPair = $keyPairs[$mailboxAddress];

            try {
                $entries = $valenceClient->get($mailboxAddress, $keyPair);
            } catch (\Throwable $e) {
                // This mailbox is unreachable; skip it and keep polling the
                // rest rather than aborting discovery/settlement entirely.
                $errors[] = "fetchPending2WayPayment: fetch valence mailbox \"{$mailboxAddress}\": {$e->getMessage()}";
                continue;
            }

            foreach ($entries as $druid => $details) {
                $half = $storedByDruid[$druid] ?? null;

                if ($half === null || ($details['status'] ?? null) !== self::TRANSACTION_STATUS_ACCEPTED) {
                    // Either an incoming offer (or status update) this
                    // wallet never initiated, or one of our own offers
                    // that isn't settled yet — surface both as pending.
                    $pending[$druid] = $details;
                    continue;
                }

                try {
                    $tx = KeyHelpers::decryptTransaction($half['encryptedHalf'], $this->getPassPhrase());

                    if (empty($tx['druid_info']['expectations'])) {
                        throw new \RuntimeException(
                            "fetchPending2WayPayment: stored half for druid \"{$druid}\" has no DRUID expectations"
                        );
                    }

                    // The counterparty has now filled in senderExpectation.from;
                    // replace our stored (incomplete) expectation with theirs.
                    $tx['druid_info']['expectations'][0] = $details['senderExpectation'];

                    $this->submitTwoWayHalf($this->mempoolHost, $tx);
                } catch (\Throwable $e) {
                    $errors[] = "fetchPending2WayPayment: settle druid \"{$druid}\": {$e->getMessage()}";
                    continue;
                }

                try {
                    $valenceClient->delete($druid, $mailboxAddress, $keyPair);
                } catch (\Throwable $e) {
                    // The half is already submitted on-chain even though
                    // the valence entry couldn't be cleaned up — this is
                    // committed progress and must still be reported settled.
                    $errors[] = "fetchPending2WayPayment: delete settled valence entry for druid \"{$druid}\": {$e->getMessage()}";
                }

                $settled[] = $druid;
            }
        }

        return [
            'pending' => $pending,
            'settled' => $settled,
            'errors' => $errors,
        ];
    }

    /**
     * Accepts a pending two-way trade offer described by $details: pays
     * $details['senderExpectation']'s asset to the offering party, embeds
     * this party's own $details['receiverExpectation'] as its half of the
     * DRUID trade, submits the resulting transaction to
     * $details['mempoolHost'], and posts the accepted status (with
     * senderExpectation.from now filled in) back to valence. $allKeypairs
     * must include the keypair for $details['receiverExpectation']['to']
     * (this party's own address in the offer). Mirrors sdk-go's
     * Wallet.Accept2WayPayment / sdk-js's Wallet.accept2WayPayment.
     *
     * @param array<EncryptedKeypairDTO> $allKeypairs
     */
    public function accept2WayPayment(array $details, array $allKeypairs): array
    {
        return $this->handle2WTxResponse($details, self::TRANSACTION_STATUS_ACCEPTED, $allKeypairs);
    }

    /**
     * Declines a pending two-way trade offer described by $details: no
     * transaction is built or submitted, but the rejected status is posted
     * back to valence so the offering party's fetchPending2WayPayment can
     * observe it. $allKeypairs must include the keypair for
     * $details['receiverExpectation']['to'] (this party's own address in
     * the offer). Mirrors sdk-go's Wallet.Reject2WayPayment / sdk-js's
     * Wallet.reject2WayPayment.
     *
     * @param array<EncryptedKeypairDTO> $allKeypairs
     */
    public function reject2WayPayment(array $details, array $allKeypairs): array
    {
        return $this->handle2WTxResponse($details, self::TRANSACTION_STATUS_REJECTED, $allKeypairs);
    }

    /**
     * The shared implementation behind accept2WayPayment/reject2WayPayment:
     * stamps $details with $status, and — only when accepting — builds this
     * party's matching transaction half (paying details.senderExpectation's
     * asset to its address, embedding details.receiverExpectation as this
     * party's own druid_info expectation — the role-swap relative to
     * make2WayPayment) and submits it to details.mempoolHost, before
     * posting the updated status back to valence (addressed to
     * details.senderExpectation.to's mailbox, signed by this party's own —
     * details.receiverExpectation.to — keypair). Mirrors sdk-go's private
     * Wallet.handle2WTxResponse.
     *
     * @param array<EncryptedKeypairDTO> $allKeypairs
     */
    private function handle2WTxResponse(array $details, string $status, array $allKeypairs): array
    {
        [$addresses, $keyPairs] = $this->decryptKeypairsMap($allKeypairs);

        $receiverAddress = $details['receiverExpectation']['to'];

        if (!isset($keyPairs[$receiverAddress])) {
            throw new \RuntimeException("handle2WTxResponse: no keypair for receiver address \"{$receiverAddress}\"");
        }

        $receiverKeyPair = $keyPairs[$receiverAddress];

        $details['status'] = $status;

        if ($status === self::TRANSACTION_STATUS_ACCEPTED) {
            $balance = $this->fetchBalance($addresses);

            $myHalf = TxBuilder::create2WTxHalf(
                $details['druid'],
                $details['receiverExpectation'],
                $details['senderExpectation'],
                $balance,
                $keyPairs,
                $receiverAddress,
                0
            );

            $details['senderExpectation']['from'] = KeyHelpers::constructTxInsAddress($myHalf['inputs']);

            $this->submitTwoWayHalf($details['mempoolHost'], $myHalf);
        }

        $this->getValenceClient()->post($details['senderExpectation']['to'], $receiverKeyPair, $details);

        return $details;
    }

    /**
     * POSTs $tx to $host's `/v1/transactions`, with fees and
     * druid_info.genesis_hash explicitly null, matching sdk-js's two-way-
     * payment mempool submissions in make2WayPayment/handle2WTxResponse/
     * fetchPending2WayPayment. druid_info never carries genesis_hash before
     * submission (create2WTxHalf's constructed shape omits it); it is added
     * here, last, only for the wire submission.
     */
    private function submitTwoWayHalf(string $host, array $tx): array
    {
        $druidInfo = $tx['druid_info'];
        $druidInfo['genesis_hash'] = null;

        return $this->request(
            method: self::POST,
            host: $host,
            path: '/v1/transactions',
            body: [
                'transactions' => [
                    [
                        'inputs' => $tx['inputs'],
                        'outputs' => $tx['outputs'],
                        'version' => $tx['version'],
                        'druid_info' => $druidInfo,
                        'fees' => null,
                    ],
                ],
            ],
        );
    }

    /**
     * Decrypts every $encryptedKeypairs entry, returning [addresses,
     * keyPairsByAddress] — the shared shape make2WayPayment/
     * fetchPending2WayPayment/handle2WTxResponse build off of. Mirrors
     * sdk-go's private Wallet.decryptKeypairsMap.
     *
     * @param array<EncryptedKeypairDTO> $encryptedKeypairs
     *
     * @return array{0:array<int,string>,1:array<string,array>}
     */
    private function decryptKeypairsMap(array $encryptedKeypairs): array
    {
        $addresses = [];
        $keyPairs = [];

        foreach ($encryptedKeypairs as $encrypted) {
            $decrypted = $this->decryptKeypair($encrypted->getContent(), $encrypted->getNonce());
            $addresses[] = $encrypted->getAddress();
            $keyPairs[$encrypted->getAddress()] = $decrypted;
        }

        return [$addresses, $keyPairs];
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
