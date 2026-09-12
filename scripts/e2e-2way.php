<?php

declare(strict_types=1);

/**
 * Live end-to-end two-wallet 2-way (DRUID) swap against the deployed /v1
 * Lineage network + valence mailbox relay.
 *
 * Wallet A mints an item and offers it in exchange for tokens from wallet B;
 * B accepts; A settles. Both wallets' final balances are polled to confirm
 * the swap landed atomically (A ends up with the tokens, B ends up with the
 * item). Mirrors sdk-go's TestTwoWaySwap_Live (twoway_e2e_test.go).
 *
 * Wallet/keypair creation is a local crypto operation only, so it always
 * runs. Set LINEAGE_E2E_WRITE=1 to also fund both wallets from the miner
 * faucet and drive the swap itself against the live network.
 *
 * Usage:
 *   php scripts/e2e-2way.php                         # local setup only
 *   LINEAGE_E2E_WRITE=1 php scripts/e2e-2way.php      # + full live swap
 */

require __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Client as HttpClient;
use Lineage\Client;

$mempoolHost = 'https://mempool.lineage.to';
$storageHost = 'https://storage.lineage.to';
$valenceHost = 'https://valence.lineage.to';
$minerHost = 'https://miner.lineage.to';

const ITEM_AMOUNT = 50; // items A mints and offers
const TOKEN_AMOUNT = 100; // tokens B pays and A receives
const FUND_TOKENS_A = 1000; // just enough for A to exist as a funded address
const FUND_TOKENS_B = 1000; // must cover TOKEN_AMOUNT

$failures = 0;

/**
 * Run $fn, print "$name ... ok" or "$name ... ERR: <message>", and return
 * $fn's result (or null on failure).
 */
function step(string $name, callable $fn): mixed
{
    global $failures;

    echo str_pad($name, 42, '.');

    try {
        $result = $fn();
        echo " ok\n";

        return $result;
    } catch (\Throwable $e) {
        $failures++;
        echo ' ERR: ' . $e->getMessage() . "\n";

        return null;
    }
}

/**
 * Poll $check up to $attempts times (sleeping $delaySeconds between each)
 * until it returns true. Prints whether/when it was confirmed.
 */
function pollUntil(string $label, callable $check, int $attempts = 24, int $delaySeconds = 5): bool
{
    for ($i = 0; $i < $attempts; $i++) {
        if ($check()) {
            echo "  {$label}: confirmed after " . ($i + 1) . " poll(s)\n";

            return true;
        }

        sleep($delaySeconds);
    }

    echo "  {$label}: NOT confirmed after {$attempts} polls\n";

    return false;
}

function fundFromMiner(string $minerHost, string $address, int $amount): array
{
    $http = new HttpClient(['http_errors' => false]);
    $response = $http->post($minerHost . '/v1/payments', [
        'json' => [
            'kind' => 'address',
            'address' => $address,
            'amount' => $amount,
            'passphrase' => '',
        ],
    ]);

    $status = $response->getStatusCode();
    if ($status < 200 || $status >= 300) {
        throw new \RuntimeException("miner funding failed: HTTP {$status} " . $response->getBody());
    }

    return json_decode((string) $response->getBody(), true);
}

echo "== Lineage sdk-php 2-way (DRUID) e2e ==\n";
echo "mempool: {$mempoolHost}\n";
echo "storage: {$storageHost}\n";
echo "valence: {$valenceHost}\n\n";

echo "-- local setup --\n";

$clientA = new Client($mempoolHost, $storageHost, null, $valenceHost);
$clientB = new Client($mempoolHost, $storageHost, null, $valenceHost);

$clientA->setPassPhrase('lineage-e2e-2way-a-' . bin2hex(random_bytes(4)));
$clientB->setPassPhrase('lineage-e2e-2way-b-' . bin2hex(random_bytes(4)));

$walletA = step('A: createWallet', fn () => $clientA->createWallet());
$walletB = step('B: createWallet', fn () => $clientB->createWallet());

if ($walletA === null || $walletB === null) {
    echo "cannot continue without wallets\n";
    exit(1);
}

step('A: openWallet', fn () => $clientA->openWallet($walletA));
step('B: openWallet', fn () => $clientB->openWallet($walletB));

$kpA = step('A: createKeypair', fn () => $clientA->createKeypair());
$kpB = step('B: createKeypair', fn () => $clientB->createKeypair());

if ($kpA === null || $kpB === null) {
    echo "cannot continue without keypairs\n";
    exit(1);
}

echo "A address: {$kpA->getAddress()}\n";
echo "B address: {$kpB->getAddress()}\n\n";

if (getenv('LINEAGE_E2E_WRITE') !== '1') {
    echo "LINEAGE_E2E_WRITE not set to 1 - skipping the live swap.\n";
    exit($failures > 0 ? 1 : 0);
}

echo "-- wallet A: fund + mint item --\n";

step('A: fund from miner', fn () => fundFromMiner($minerHost, $kpA->getAddress(), FUND_TOKENS_A));

pollUntil('A funded', function () use ($clientA, $kpA) {
    $balance = $clientA->fetchBalance([$kpA->getAddress()]);

    return ($balance['total']['tokens'] ?? 0) > 0;
});

$itemResult = step('A: createItems', fn () => $clientA->createItems($kpA, true, ITEM_AMOUNT));

$genesisHash = $itemResult['asset']['genesis_hash'] ?? null;

if ($genesisHash === null) {
    echo "cannot continue without a genesis hash from createItems\n";
    exit(1);
}

pollUntil('A item minted', function () use ($clientA, $kpA, $genesisHash) {
    $balance = $clientA->fetchBalance([$kpA->getAddress()]);

    return ($balance['total']['items'][$genesisHash] ?? 0) >= ITEM_AMOUNT;
});

echo "\n-- wallet B: fund with tokens --\n";

step('B: fund from miner', fn () => fundFromMiner($minerHost, $kpB->getAddress(), FUND_TOKENS_B));

pollUntil('B funded', function () use ($clientB, $kpB) {
    $balance = $clientB->fetchBalance([$kpB->getAddress()]);

    return ($balance['total']['tokens'] ?? 0) >= TOKEN_AMOUNT;
});

echo "\n-- A: make2WayPayment (offer item, want tokens) --\n";

$half = step(
    'A: make2WayPayment',
    fn () => $clientA->make2WayPayment(
        $kpB->getAddress(),
        \Lineage\Serialization::assetItem(ITEM_AMOUNT, $genesisHash, null), // sendingAsset: A's item
        \Lineage\Serialization::assetToken(TOKEN_AMOUNT), // receivingAsset: tokens A wants
        [$kpA],
        $kpA
    )
);

if ($half === null) {
    echo "cannot continue without a pending half\n";
    exit(1);
}

// The caller is responsible for persisting the pending half returned by
// make2WayPayment until fetchPending2WayPayment reports it settled; here
// that's simply this local variable, since both parties run in this one
// script/process.
$storedHalf = $half;

echo "\n-- B: fetchPending2WayPayment sees the offer, then accept2WayPayment --\n";

$offer = step('B: fetchPending2WayPayment (sees offer)', function () use ($clientB, $kpB, $half) {
    $result = $clientB->fetchPending2WayPayment([], [$kpB]);

    if (!isset($result['pending'][$half['druid']])) {
        throw new \RuntimeException("B did not see A's offer for druid {$half['druid']}");
    }

    return $result['pending'][$half['druid']];
});

if ($offer === null) {
    echo "cannot continue without B having seen the offer\n";
    exit(1);
}

step('B: accept2WayPayment', fn () => $clientB->accept2WayPayment($offer, [$kpB]));

echo "\n-- A: fetchPending2WayPayment settles the swap --\n";

step('A: fetchPending2WayPayment (settle)', function () use ($clientA, $kpA, $storedHalf) {
    $result = $clientA->fetchPending2WayPayment([$storedHalf], [$kpA]);

    if (!in_array($storedHalf['druid'], $result['settled'], true)) {
        throw new \RuntimeException(
            "druid {$storedHalf['druid']} was not settled (settled=" . json_encode($result['settled']) . ')'
        );
    }
});

echo "\n-- poll final balances: A should hold the tokens, B should hold the item --\n";

$aSettled = pollUntil('A tokens landed', function () use ($clientA, $kpA) {
    $balance = $clientA->fetchBalance([$kpA->getAddress()]);

    return ($balance['total']['tokens'] ?? 0) >= TOKEN_AMOUNT;
});

$bSettled = pollUntil('B item landed', function () use ($clientB, $kpB, $genesisHash) {
    $balance = $clientB->fetchBalance([$kpB->getAddress()]);

    return ($balance['total']['items'][$genesisHash] ?? 0) >= ITEM_AMOUNT;
});

if (!$aSettled) {
    $failures++;
    echo "A: expected >= " . TOKEN_AMOUNT . " tokens after the swap, but they never landed\n";
}

if (!$bSettled) {
    $failures++;
    echo "B: expected >= " . ITEM_AMOUNT . " items after the swap, but they never landed\n";
}

echo "\ndone. failures: {$failures}\n";
exit($failures > 0 ? 1 : 0);
