# Lineage PHP SDK

PHP SDK for the Lineage `/v1` REST API: a keyless read client and a key-holding wallet that signs transactions locally.

## Installation

```
composer require lineage/php
```

Requires PHP >= 8.4, the `sodium` extension, and Composer.

## Configuration

`Lineage\Client` talks to two hosts:

- **`mempoolHost`** – accepts writes (items, payments) and answers live queries
  (balances, supply, transaction status).
- **`storageHost`** – serves stored chain history (blocks, blockchain entries).
  Can be the same host as `mempoolHost`, or a dedicated read/storage node.

An optional **`apiKey`** is sent as the `x-api-key` header on every request. An
optional **`valenceHost`** is the plaintext mailbox relay that 2-way payments
(`make2WayPayment`/`fetchPending2WayPayment`/`accept2WayPayment`/`reject2WayPayment`)
exchange DRUID trade offers through; it's only required if you use those methods.

```php
use Lineage\Client;

$client = new Client(
    mempoolHost: 'https://mempool.lineage.to',
    storageHost: 'https://storage.lineage.to',
    apiKey: 'your-api-key', // optional
    valenceHost: 'https://valence.lineage.to', // optional, required for 2-way payments
);
```

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

// Check its balance (new/transferred assets appear here only once the mempool confirms them).
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

## Two-way (DRUID) payments

DRUID-based dual double-entry trades: two parties each pay an asset to the other,
atomically correlated by a shared DRUID, and coordinated out-of-band through a
plaintext valence mailbox host (`valenceHost`, see Configuration above).

```php
// Party A offers to pay $sendingAsset to $paymentAddress in exchange for
// $receivingAsset delivered to $receiveKeypair's address. Persist the
// returned pending half until fetchPending2WayPayment reports it settled.
$pendingHalf = $client->make2WayPayment($paymentAddress, $sendingAsset, $receivingAsset, $allKeypairs, $receiveKeypair);

// Both parties poll their own mailboxes: incoming offers are surfaced as
// 'pending'; offers this wallet made that the counterparty has accepted are
// submitted and reported as 'settled'.
['pending' => $pending, 'settled' => $settled] = $client->fetchPending2WayPayment($storedPendingHalves, $allKeypairs);

// Party B accepts (submits its half and notifies valence) or rejects
// (notifies valence only) an offer found in $pending.
$client->accept2WayPayment($details, $allKeypairs);
$client->reject2WayPayment($details, $allKeypairs);
```

Two-way trades interoperate across all the SDKs and settle atomically through the mempool's DRUID pool, so either party can be on any SDK.

## Wire compatibility

Keys and signatures are byte-for-byte compatible across every Lineage SDK — a wallet (mnemonic) created in one derives the same addresses and produces the same signatures in all of them. sdk-js is the reference implementation; BIP39/BIP32 derivation, SHA3-256 addresses, ed25519 signing, and the `/v1` transaction serialization (field order is load-bearing — you sign exactly what you submit) all match it exactly.

## Testing

```
vendor/bin/phpunit
```

The suite asserts against golden test vectors (`tests/fixtures/*.json`) generated from
sdk-js's own crypto primitives, not a reimplementation of the same logic.
`scripts/e2e.php` and `scripts/e2e-2way.php` exercise live production hosts (plus
`valence.lineage.to` for the latter); both require `LINEAGE_E2E_WRITE=1` to write, and
both are excluded from the default CI workflow (`.github/workflows/ci.yml`).

## Lineage SDKs

- [JavaScript / TypeScript](https://github.com/lineage-foundation/sdk-js)
- [Python](https://github.com/lineage-foundation/sdk-python)
- [Go](https://github.com/lineage-foundation/sdk-go)
- [Rust](https://github.com/lineage-foundation/sdk-rust)
- [PHP](https://github.com/lineage-foundation/sdk-php)
- [Laravel](https://github.com/lineage-foundation/sdk-laravel)

## License

MIT — see [LICENSE](LICENSE).
