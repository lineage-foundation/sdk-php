<?php

declare(strict_types=1);

namespace Lineage\Tests;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Lineage\Client;
use Lineage\DTO\EncryptedKeypairDTO;
use Lineage\Functions\KeyHelpers;
use Lineage\Serialization;
use PHPUnit\Framework\TestCase;

class ClientWriteTest extends TestCase
{
    private const MEMPOOL_HOST = 'https://mempool.example';
    private const STORAGE_HOST = 'https://storage.example';
    private const API_KEY = 'test-api-key';

    private const NONCE = 'abcdefghijklmnopqrstuvwx';

    private array $lastHistory = [];

    private function vector(string $name): array
    {
        return json_decode(file_get_contents(__DIR__ . '/fixtures/' . $name . '.json'), true);
    }

    private function makeClient(array $responses): Client
    {
        $container = [];
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));

        $client = new Client(self::MEMPOOL_HOST, self::STORAGE_HOST, self::API_KEY);
        $client->setHttpClient(new HttpClient(['handler' => $stack]));

        $this->lastHistory = &$container;

        return $client;
    }

    /**
     * createItems must POST /v1/items with a body byte-identical to
     * item.json's vector `payload`, with the legacy `version` field
     * stripped (sdk-js's actual request interface omits it) — the same
     * shape sdk-go's TestCreateItems_MatchesVector asserts.
     */
    public function testCreateItemsMatchesVectorPayload(): void
    {
        $v = $this->vector('item');

        $publicKey = sodium_hex2bin($v['publicKey']);
        $secretKey = sodium_hex2bin($v['secretKey']);
        $address = KeyHelpers::constructAddress($publicKey);

        $this->assertSame(
            $v['payload']['script_public_key'],
            $address,
            'sanity: derived address must equal the vector script_public_key'
        );

        $passphraseKey = KeyHelpers::passphraseKey('item-test-pass');
        $encrypted = KeyHelpers::encryptKeypair($publicKey, $secretKey, $passphraseKey, self::NONCE);
        $keypair = new EncryptedKeypairDTO($address, $encrypted['nonce'], $encrypted['save']);

        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'asset' => ['kind' => 'item', 'amount' => $v['amount']],
                'to_address' => $address,
                'tx_hash' => 'deadbeef',
            ])),
        ]);
        $client->setPassPhrase('item-test-pass');

        $client->createItems($keypair, $v['defaultGenesisHashSpec'], (int) $v['amount'], $v['metadata']);

        $this->assertCount(1, $this->lastHistory);
        $request = $this->lastHistory[0]['request'];

        $this->assertSame('POST', $request->getMethod());
        $this->assertSame(self::MEMPOOL_HOST . '/v1/items', (string) $request->getUri());
        $this->assertSame(self::API_KEY, $request->getHeaderLine('x-api-key'));

        // Independent (vector-vs-observed) check: derive the expected wire
        // body straight from the vector's own payload, only removing the
        // legacy "version" field, without re-marshaling through any of the
        // Client's own struct-building code.
        $expectedPayload = $v['payload'];
        unset($expectedPayload['version']);
        $wantBody = Serialization::json($expectedPayload);

        $this->assertSame($wantBody, (string) $request->getBody());

        $gotBody = json_decode((string) $request->getBody(), true);
        $this->assertSame($v['payload']['signature'], $gotBody['signature'], 'byte-exact signature');
    }

    /**
     * makeTokenPayment must first fetch the balance (POST
     * /v1/balances/query) then submit `POST /v1/transactions` with a body
     * byte-identical to `{"transactions":[{...payment.json's createTx,"fees":null}]}`.
     */
    public function testMakeTokenPaymentMatchesVectorPayload(): void
    {
        $v = $this->vector('payment');
        $derivation = $this->vector('derivation');

        $senderSecretKeyHex = null;
        foreach ($derivation['depths'] as $d) {
            if ($d['publicKey'] === $v['senderPublicKey'] && $d['address'] === $v['senderAddress']) {
                $senderSecretKeyHex = $d['secretKey'];
                break;
            }
        }
        $this->assertNotNull(
            $senderSecretKeyHex,
            'no derivation.json entry matches senderPublicKey/senderAddress from payment.json'
        );

        $passphraseKey = KeyHelpers::passphraseKey('payment-test-pass');
        $encrypted = KeyHelpers::encryptKeypair(
            sodium_hex2bin($v['senderPublicKey']),
            sodium_hex2bin($senderSecretKeyHex),
            $passphraseKey,
            self::NONCE
        );
        $senderKeypair = new EncryptedKeypairDTO($v['senderAddress'], $encrypted['nonce'], $encrypted['save']);

        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'balance' => $v['fetchBalanceResponse'],
            ])),
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'transactions' => new \stdClass(),
            ])),
        ]);
        $client->setPassPhrase('payment-test-pass');

        $client->makeTokenPayment(
            $v['paymentAddress'],
            (int) $v['paymentAsset']['Token'],
            [$senderKeypair],
            $senderKeypair,
            (int) $v['locktime']
        );

        $this->assertCount(2, $this->lastHistory);

        $balanceRequest = $this->lastHistory[0]['request'];
        $this->assertSame('POST', $balanceRequest->getMethod());
        $this->assertSame(self::MEMPOOL_HOST . '/v1/balances/query', (string) $balanceRequest->getUri());
        $this->assertSame(
            ['addresses' => [$v['senderAddress']]],
            json_decode((string) $balanceRequest->getBody(), true)
        );

        $txRequest = $this->lastHistory[1]['request'];
        $this->assertSame('POST', $txRequest->getMethod());
        $this->assertSame(self::MEMPOOL_HOST . '/v1/transactions', (string) $txRequest->getUri());

        $expectedTx = $v['createTxPayload']['createTx'];
        $expectedTx['fees'] = null;
        $wantBody = Serialization::json(['transactions' => [$expectedTx]]);

        $this->assertSame($wantBody, (string) $txRequest->getBody());
    }

    /**
     * Proves the keystore convention is reconciled: a keypair produced by
     * KeyHelpers::getNewKeypair decrypts via KeyHelpers::decryptKeypair
     * under the same passphraseKey.
     */
    public function testGetNewKeypairRoundTripsThroughDecryptKeypair(): void
    {
        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        $passphraseKey = KeyHelpers::passphraseKey('round-trip-pass');

        $kp = KeyHelpers::getNewKeypair($mnemonic, $passphraseKey, []);

        $decrypted = KeyHelpers::decryptKeypair($kp['save'], $kp['nonce'], $passphraseKey);

        $this->assertSame(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen($decrypted['publicKey']));
        $this->assertSame(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, strlen($decrypted['secretKey']));
        $this->assertSame($kp['address'], KeyHelpers::constructAddress($decrypted['publicKey']));
    }

    /**
     * End-to-end: the whole Client wallet flow (createWallet -> openWallet
     * -> createKeypair) must produce a keypair that decrypts via
     * decryptKeypair, proving getNewKeypair/createWallet/openWallet all
     * agree on the same aligned encrypt/decrypt convention.
     */
    public function testClientWalletFlowProducesADecryptableKeypair(): void
    {
        $client = new Client(self::MEMPOOL_HOST, self::STORAGE_HOST, self::API_KEY);
        $client->setPassPhrase('wallet-flow-pass');

        $wallet = $client->createWallet();
        $this->assertNotNull($wallet->getSeedPhrase());
        $this->assertTrue($client->openWallet($wallet));

        $keypair = $client->createKeypair();

        $passphraseKey = KeyHelpers::passphraseKey('wallet-flow-pass');
        $decrypted = KeyHelpers::decryptKeypair($keypair->getContent(), $keypair->getNonce(), $passphraseKey);

        $this->assertSame($keypair->getAddress(), KeyHelpers::constructAddress($decrypted['publicKey']));
    }
}
