<?php

declare(strict_types=1);

/**
 * Live end-to-end smoke test against the deployed /v1 Lineage network.
 *
 * By default this only exercises the READ methods (getSupply, getLatestBlock,
 * getBlock, fetchBalance, getTransactionStatus) against the production hosts
 * and requires no environment configuration.
 *
 * Set LINEAGE_E2E_WRITE=1 to also exercise the write path: a wallet and two
 * keypairs are created locally, then (if LINEAGE_E2E_FUND=1 as well) the
 * sender address is funded via the miner's `POST /v1/payments` endpoint, its
 * balance is polled until the funding lands, and createItems /
 * makeTokenPayment / makeItemPayment are run against it, polling the
 * recipient's balance to confirm.
 *
 * Usage:
 *   php scripts/e2e.php                                    # reads only
 *   LINEAGE_E2E_WRITE=1 php scripts/e2e.php                 # + local wallet/keypair writes (unfunded)
 *   LINEAGE_E2E_WRITE=1 LINEAGE_E2E_FUND=1 php scripts/e2e.php   # + miner funding + on-chain writes
 */

require __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Client as HttpClient;
use Lineage\Client;

$mempoolHost = 'https://mempool.lineage.to';
$storageHost = 'https://storage.lineage.to';
$minerHost = 'https://miner.lineage.to';

$client = new Client($mempoolHost, $storageHost);

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
function pollUntil(string $label, callable $check, int $attempts = 20, int $delaySeconds = 3): bool
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

echo "== Lineage sdk-php e2e ==\n";
echo "mempool: {$mempoolHost}\n";
echo "storage: {$storageHost}\n\n";

echo "-- reads --\n";

step('getSupply', fn () => $client->getSupply());

$latestBlock = step('getLatestBlock', fn () => $client->getLatestBlock());

$blockNum = (int) ($latestBlock['block']['b_num'] ?? 1);
step('getBlock', fn () => $client->getBlock($blockNum));

// A freshly generated (never-funded) wallet address, purely to exercise
// fetchBalance against an address with no on-chain history. Generating this
// wallet/keypair is a local crypto operation only — it makes no network
// request and needs no write-path env flag.
$client->setPassPhrase('lineage-e2e-read-passphrase');
$readWallet = $client->createWallet();
$client->openWallet($readWallet);
$readKeypair = $client->createKeypair();

step('fetchBalance', fn () => $client->fetchBalance([$readKeypair->getAddress()]));

step('getTransactionStatus', fn () => $client->getTransactionStatus([str_repeat('0', 64)]));

echo "\n";

if (getenv('LINEAGE_E2E_WRITE') !== '1') {
    echo "LINEAGE_E2E_WRITE not set to 1 - skipping write flow.\n";
    exit($failures > 0 ? 1 : 0);
}

echo "-- writes --\n";

$client->setPassPhrase('lineage-e2e-write-' . bin2hex(random_bytes(4)));

$wallet = step('createWallet', fn () => $client->createWallet());
$client->openWallet($wallet);

$senderKeypair = step('createKeypair (sender)', fn () => $client->createKeypair());
$excessKeypair = $senderKeypair === null
    ? null
    : step('createKeypair (excess)', fn () => $client->createKeypair([$senderKeypair->getAddress()]));

if ($senderKeypair === null || $excessKeypair === null) {
    echo "cannot continue without keypairs\n";
    exit(1);
}

echo "sender address: {$senderKeypair->getAddress()}\n";
echo "excess address: {$excessKeypair->getAddress()}\n";

if (getenv('LINEAGE_E2E_FUND') === '1') {
    step('fund sender from miner', function () use ($minerHost, $senderKeypair) {
        $http = new HttpClient(['http_errors' => false]);
        $response = $http->post($minerHost . '/v1/payments', [
            'json' => [
                'kind' => 'address',
                'address' => $senderKeypair->getAddress(),
                'amount' => 10000000000,
                'passphrase' => '',
            ],
        ]);

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException("miner funding failed: HTTP {$status} " . $response->getBody());
        }

        return json_decode((string) $response->getBody(), true);
    });

    pollUntil('sender funded', function () use ($client, $senderKeypair) {
        $balance = $client->fetchBalance([$senderKeypair->getAddress()]);

        return ($balance['total']['tokens'] ?? 0) > 0;
    });

    $itemResult = step('createItems', fn () => $client->createItems($senderKeypair, true, 10));

    $genesisHash = $itemResult['asset']['genesis_hash'] ?? null;

    step(
        'makeTokenPayment',
        fn () => $client->makeTokenPayment(
            $excessKeypair->getAddress(),
            1000,
            [$senderKeypair],
            $senderKeypair
        )
    );

    if ($genesisHash !== null) {
        step(
            'makeItemPayment',
            fn () => $client->makeItemPayment(
                $excessKeypair->getAddress(),
                1,
                $genesisHash,
                [$senderKeypair],
                $senderKeypair
            )
        );
    } else {
        echo str_pad('makeItemPayment', 42, '.') . " SKIPPED (no genesis hash from createItems)\n";
    }

    pollUntil('excess address received funds', function () use ($client, $excessKeypair) {
        $balance = $client->fetchBalance([$excessKeypair->getAddress()]);

        return ($balance['total']['tokens'] ?? 0) > 0;
    });
} else {
    echo "LINEAGE_E2E_FUND not set to 1 - skipping miner funding + on-chain writes.\n";
}

echo "\ndone. failures: {$failures}\n";
exit($failures > 0 ? 1 : 0);
