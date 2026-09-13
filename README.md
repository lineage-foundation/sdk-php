# lineage/php

Composer package for the Lineage blockchain's `/v1` API: wallets, keypairs, item
assets, and token/item payments.

## Requirements

- PHP >= 8.2
- The `sodium` extension (bundled with PHP core since 7.2)
- Composer

## Installation

```
composer require lineage/php
```

## Configuration

`Lineage\Client` talks to two hosts:

- **`mempoolHost`** – the node that accepts writes (items, payments) and answers
  live queries (balances, supply, transaction status).
- **`storageHost`** – the node that serves stored chain history (blocks, blockchain
  entries). This can be the same host as `mempoolHost`, or a dedicated
  read/storage node.

An optional **`apiKey`** is sent as the `x-api-key` header on every request, if set.

```php
use Lineage\Client;

$client = new Client(
    mempoolHost: 'https://mempool.lineage.to',
    storageHost: 'https://storage.lineage.to',
    apiKey: 'your-api-key', // optional
);
```

There is no `computeHost`/`intercomHost` split any more — the legacy compute/intercom
node pair has been replaced by the unified `/v1` mempool/storage API above.

## Quickstart

```php
use Lineage\Client;

$client = new Client('https://mempool.lineage.to', 'https://storage.lineage.to');

// A pass phrase encrypts/decrypts the wallet and every keypair derived from it.
// Set it before creating or opening a wallet.
$client->setPassPhrase('my very intricate passphrase');

// Create a new wallet. The returned DTO carries the 12-word BIP39 seed phrase –
// store it (and the encrypted wallet) securely; it's the only way to recover funds.
$wallet = $client->createWallet();
echo $wallet->getSeedPhrase();

// Open the wallet (decrypts it in memory) before deriving keypairs.
$client->openWallet($wallet);

// Derive a new address/keypair from the open wallet.
$keypair = $client->createKeypair();
echo $keypair->getAddress();

// Check its balance.
$balance = $client->fetchBalance([$keypair->getAddress()]);

// Create 10 item assets ("Items", the Lineage equivalent of NFTs) at $keypair's
// address, using the well-known default genesis hash.
$itemResult = $client->createItems($keypair, defaultGenesisHash: true, amount: 10);

// Send 1000 Token assets from $keypair to another address, with change (excess)
// returned to $keypair itself.
$client->makeTokenPayment(
    paymentAddress: $recipientAddress,
    amount: 1000,
    allKeypairs: [$keypair],
    excessKeypair: $keypair,
);
```

Note that a newly created/transferred asset will only show up in a subsequent
`fetchBalance` call once it has been confirmed by the mempool.

## Usage reference

### Wallets and keypairs

```php
$wallet = $client->createWallet();               // new wallet + seed phrase
$wallet = $client->createWallet($seedPhrase);     // restore from an existing seed phrase
$opened = $client->openWallet($wallet);           // bool
$keypair = $client->createKeypair();              // EncryptedKeypairDTO
$keypair = $client->createKeypair($existingAddresses); // skip already-issued addresses
```

### Reads

```php
$client->getSupply();                        // total/issued token supply
$client->getLatestBlock();                   // most recently stored block
$client->getBlock($num);                     // a stored block by number
$client->getBlockchainEntry($key);           // a stored block or transaction by key
$client->fetchBalance($addresses);           // UTXO balances for one or more addresses
$client->getTransactionStatus($hashes);      // mempool status for one or more tx hashes
```

### Writes

```php
$client->createItems($keypair, $defaultGenesisHash = true, $amount = 1000, $metadata = null);

$client->makeTokenPayment($paymentAddress, $amount, $allKeypairs, $excessKeypair, $locktime = 0);

$client->makeItemPayment($paymentAddress, $amount, $genesisHash, $allKeypairs, $excessKeypair, $metadata = null, $locktime = 0);
```

`$allKeypairs` is an array of `EncryptedKeypairDTO`s whose combined balance funds the
payment; `$excessKeypair` receives the change output.

### 2-way payments (deferred)

`createTradeRequest`, `getPendingTransactions`, `acceptPendingTransaction` and
`rejectPendingTransaction` (DRUID-based dual double-entry trades) are **not yet
implemented** against `/v1` — each throws `Lineage\Exceptions\NotImplemented` until the
corresponding `/v1` endpoints land.

## Wire compatibility with sdk-js

This SDK is built to be byte-for-byte compatible with
[`sdk-js`](https://github.com/lineage-foundation/sdk-js) (the canonical reference
implementation) at every layer that touches the wire or a signature:

- BIP39/BIP32 key derivation (the same mnemonic derives the same keypairs and
  addresses as sdk-js/sdk-go/sdk-python).
- The sha3-256 transaction/item signable hash and the JSON preimage it's computed
  over.
- ed25519 signing/verification.
- The passphrase-derived keystore encryption used to seal keypairs and wallet
  mnemonics at rest.
- The `/v1` request/response JSON shapes themselves, including field order — `/v1`
  responses preserve key order so that "sign what you see" workflows are safe.

In practice, this means a wallet/seed phrase created by sdk-js (or sdk-go, or
sdk-python) can be opened by this SDK with `createWallet($seedPhrase)` — or vice
versa — and will derive identical keypairs and addresses, and a transaction signed by
any one of these SDKs is verifiable, and spendable, by a node regardless of which SDK
built it.

This is enforced by a shared set of golden test vectors (`tests/fixtures/*.json`)
generated from sdk-js's own internal crypto primitives — this SDK's unit tests
(`vendor/bin/phpunit`) assert against those vectors directly, not against a
reimplementation of the same logic.

## Live end-to-end script

`scripts/e2e.php` exercises this SDK against the live production hosts
(`mempool.lineage.to` / `storage.lineage.to`):

```
php scripts/e2e.php
```

By default it only runs the read methods (`getSupply`, `getLatestBlock`, `getBlock`,
`fetchBalance`, `getTransactionStatus`) and requires no configuration. Set
`LINEAGE_E2E_WRITE=1` to also create a wallet and keypairs locally, and additionally
`LINEAGE_E2E_FUND=1` to fund the sender from the miner and exercise `createItems`,
`makeTokenPayment` and `makeItemPayment` against the live network. This live e2e is
intentionally kept out of the default CI workflow (`.github/workflows/ci.yml`), which
only runs the vector-backed unit test suite.

## Links

- [Lineage Foundation](https://lineage.foundation)
- [Other SDKs](https://github.com/lineage-foundation) – sdk-go, sdk-python, sdk-js, sdk-laravel

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT – see [LICENSE](LICENSE).
