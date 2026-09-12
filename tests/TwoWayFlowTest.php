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
use Lineage\ValenceClient;
use PHPUnit\Framework\TestCase;

class TwoWayFlowTest extends TestCase
{
    private const MEMPOOL_HOST = 'https://mempool.example';
    private const STORAGE_HOST = 'https://storage.example';
    private const VALENCE_HOST = 'https://valence.example';
    private const API_KEY = 'test-api-key';
    private const PASS_PHRASE = 'two-way-test-pass';

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

        $client = new Client(self::MEMPOOL_HOST, self::STORAGE_HOST, self::API_KEY, self::VALENCE_HOST);
        $client->setHttpClient(new HttpClient(['handler' => $stack]));
        $client->setPassPhrase(self::PASS_PHRASE);

        $this->lastHistory = &$container;

        return $client;
    }

    /**
     * Derive an EncryptedKeypairDTO from raw hex public/secret keys (as
     * given by twoway.json's fixedKeypairs), sealed under
     * self::PASS_PHRASE so it round-trips through Client::decryptKeypair.
     */
    private function keypairDTOFromHex(string $address, string $publicKeyHex, string $secretKeyHex): EncryptedKeypairDTO
    {
        $passphraseKey = KeyHelpers::passphraseKey(self::PASS_PHRASE);
        $encrypted = KeyHelpers::encryptKeypair(hex2bin($publicKeyHex), hex2bin($secretKeyHex), $passphraseKey);

        return new EncryptedKeypairDTO($address, $encrypted['nonce'], $encrypted['save']);
    }

    private function balanceResponse(string $address, int $tokens): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'balance' => [
                'total' => ['tokens' => $tokens, 'items' => new \stdClass()],
                'address_list' => [
                    $address => [
                        ['out_point' => ['t_hash' => '000000', 'n' => 0], 'value' => ['Token' => $tokens]],
                    ],
                ],
            ],
        ]));
    }

    private function jsonResponse(array $body): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode($body));
    }

    // (a) valence POST auth headers + plaintext offer body must match
    // twoway.json's valence-auth vector exactly.
    public function testValenceClientPostMatchesAuthVectorAndSendsPlaintext(): void
    {
        $v = $this->vector('twoway');
        $kp = $v['fixedKeypairs']['ours'][0];
        $keyPair = ['publicKey' => hex2bin($kp['public_key']), 'secretKey' => hex2bin($kp['secret_key'])];
        $offer = $v['pending2WTxDetailsOffer'];

        $container = [];
        $mock = new MockHandler([$this->jsonResponse([])]);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        $guzzle = new HttpClient(['handler' => $stack]);

        $valenceClient = new ValenceClient(self::VALENCE_HOST, $guzzle);
        $valenceClient->post($kp['address'], $keyPair, $offer);

        $this->assertCount(1, $container);
        $request = $container[0]['request'];

        $this->assertSame('POST', $request->getMethod());
        $this->assertSame(self::VALENCE_HOST . '/messages', (string) $request->getUri());

        $this->assertSame($v['valenceAuth']['address'], $request->getHeaderLine('address'));
        $this->assertSame($v['valenceAuth']['public_key'], $request->getHeaderLine('public_key'));
        $this->assertSame($v['valenceAuth']['signature'], $request->getHeaderLine('signature'));

        $wantBody = Serialization::json(['id' => $offer['druid'], 'data' => $offer]);
        $this->assertSame($wantBody, (string) $request->getBody(), 'valence offer body must be sent in plaintext');
    }

    // (b) ACCEPTOR discovery: no stored halves, an offer sitting in our own
    // mailbox must still be surfaced in 'pending'.
    public function testFetchPendingDiscoversIncomingOfferWithNoStoredHalves(): void
    {
        $v = $this->vector('twoway');
        $ourKp = $v['fixedKeypairs']['ours'][0];
        $ours = $this->keypairDTOFromHex($ourKp['address'], $ourKp['public_key'], $ourKp['secret_key']);

        $offer = $v['pending2WTxDetailsOffer'];
        $druid = $offer['druid'];

        $client = $this->makeClient([
            $this->jsonResponse([$druid => $offer]),
        ]);

        $result = $client->fetchPending2WayPayment([], [$ours]);

        $this->assertSame([], $result['settled']);
        $this->assertArrayHasKey($druid, $result['pending']);
        $this->assertSame($offer, $result['pending'][$druid]);

        $this->assertCount(1, $this->lastHistory);
        $getRequest = $this->lastHistory[0]['request'];
        $this->assertSame('GET', $getRequest->getMethod());
        $this->assertSame(self::VALENCE_HOST . '/messages', (string) $getRequest->getUri());
        $this->assertSame($ourKp['address'], $getRequest->getHeaderLine('address'));
        $this->assertSame($ourKp['public_key'], $getRequest->getHeaderLine('public_key'));
    }

    // (c) INITIATOR settle: an offer we made, now accepted by the
    // counterparty, must be decrypted, submitted with the counterparty's
    // filled-in senderExpectation, deleted from valence, and reported settled.
    public function testFetchPendingSettlesAcceptedStoredHalf(): void
    {
        $myAddress = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
        $otherAddress = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2';

        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        $passphraseKey = KeyHelpers::passphraseKey(self::PASS_PHRASE);
        $rawKp = KeyHelpers::deriveKeypair($mnemonic, '', 0);
        $encrypted = KeyHelpers::encryptKeypair($rawKp['publicKey'], $rawKp['secretKey'], $passphraseKey);
        $mine = new EncryptedKeypairDTO($rawKp['address'], $encrypted['nonce'], $encrypted['save']);

        $sendingAsset = Serialization::assetToken(100);
        $receivingAsset = Serialization::assetToken(50);

        // Phase 1: make the offer, capturing the pending half to store.
        $makeClient = $this->makeClient([
            $this->balanceResponse($rawKp['address'], 500),
            $this->jsonResponse([]),
        ]);

        $half = $makeClient->make2WayPayment($otherAddress, $sendingAsset, $receivingAsset, [$mine], $mine);

        // The counterparty has since accepted: fills senderExpectation.from
        // with their own construct-tx-ins-address and flips status.
        $counterpartyFilledSenderExpectation = $half['senderExpectation'];
        $counterpartyFilledSenderExpectation['from'] = 'counterparty-tx-ins-address';

        $acceptedDetails = [
            'druid' => $half['druid'],
            'senderExpectation' => $counterpartyFilledSenderExpectation,
            'receiverExpectation' => $half['receiverExpectation'],
            'status' => Client::TRANSACTION_STATUS_ACCEPTED,
            'mempoolHost' => self::MEMPOOL_HOST,
        ];

        // Phase 2: fetch settles it.
        $fetchClient = $this->makeClient([
            $this->jsonResponse([$half['druid'] => $acceptedDetails]),
            $this->jsonResponse(['transactions' => []]),
            $this->jsonResponse([]),
        ]);

        $result = $fetchClient->fetchPending2WayPayment([$half], [$mine]);

        $this->assertSame([$half['druid']], $result['settled']);
        $this->assertSame([], $result['pending']);

        $this->assertCount(3, $this->lastHistory);

        $submitRequest = $this->lastHistory[1]['request'];
        $this->assertSame('POST', $submitRequest->getMethod());
        $this->assertSame(self::MEMPOOL_HOST . '/v1/transactions', (string) $submitRequest->getUri());

        $submittedBody = json_decode((string) $submitRequest->getBody(), true);
        $submittedTx = $submittedBody['transactions'][0];
        $this->assertNull($submittedTx['fees']);
        $this->assertNull($submittedTx['druid_info']['genesis_hash']);
        $this->assertSame(
            $counterpartyFilledSenderExpectation,
            $submittedTx['druid_info']['expectations'][0],
            'submitted druid_info expectation must be the counterparty-filled senderExpectation, not our stored (incomplete) one'
        );

        $deleteRequest = $this->lastHistory[2]['request'];
        $this->assertSame('DELETE', $deleteRequest->getMethod());
        $this->assertSame(self::VALENCE_HOST . '/messages/' . $half['druid'], (string) $deleteRequest->getUri());
    }

    // (d) accept must submit to details.mempoolHost (not the client's own
    // configured mempoolHost), with druid_info.genesis_hash:null and fees:null.
    public function testAcceptSubmitsToDetailsMempoolHostWithNullGenesisHashAndFees(): void
    {
        $offerMempoolHost = 'https://offering-party-mempool.example';

        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        $passphraseKey = KeyHelpers::passphraseKey(self::PASS_PHRASE);
        $rawKp = KeyHelpers::deriveKeypair($mnemonic, '', 0);
        $encrypted = KeyHelpers::encryptKeypair($rawKp['publicKey'], $rawKp['secretKey'], $passphraseKey);
        $mine = new EncryptedKeypairDTO($rawKp['address'], $encrypted['nonce'], $encrypted['save']);

        $offeringPartyAddress = 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3';

        $details = [
            'druid' => 'DRUID0xdeadbeefdeadbeefdeadbeefdeadbeef',
            'senderExpectation' => ['from' => '', 'to' => $offeringPartyAddress, 'asset' => Serialization::assetToken(1000)],
            'receiverExpectation' => ['from' => '', 'to' => $rawKp['address'], 'asset' => Serialization::assetToken(50)],
            'status' => Client::TRANSACTION_STATUS_PENDING,
            'mempoolHost' => $offerMempoolHost,
        ];

        $client = $this->makeClient([
            $this->balanceResponse($rawKp['address'], 2000),
            $this->jsonResponse(['transactions' => []]),
            $this->jsonResponse([]),
        ]);

        $accepted = $client->accept2WayPayment($details, [$mine]);

        $this->assertSame(Client::TRANSACTION_STATUS_ACCEPTED, $accepted['status']);
        $this->assertNotSame('', $accepted['senderExpectation']['from'], 'senderExpectation.from must be filled by accept');

        $this->assertCount(3, $this->lastHistory);

        $balanceRequest = $this->lastHistory[0]['request'];
        $this->assertSame(self::MEMPOOL_HOST . '/v1/balances/query', (string) $balanceRequest->getUri());

        $submitRequest = $this->lastHistory[1]['request'];
        $this->assertSame('POST', $submitRequest->getMethod());
        $this->assertSame($offerMempoolHost . '/v1/transactions', (string) $submitRequest->getUri());

        $submittedBody = json_decode((string) $submitRequest->getBody(), true);
        $submittedTx = $submittedBody['transactions'][0];
        $this->assertNull($submittedTx['fees']);
        $this->assertNull($submittedTx['druid_info']['genesis_hash']);

        $valenceRequest = $this->lastHistory[2]['request'];
        $this->assertSame('POST', $valenceRequest->getMethod());
        $this->assertSame(self::VALENCE_HOST . '/messages', (string) $valenceRequest->getUri());
        $this->assertSame($offeringPartyAddress, $valenceRequest->getHeaderLine('address'));

        $postedBody = json_decode((string) $valenceRequest->getBody(), true);
        $this->assertSame('accepted', $postedBody['data']['status']);
        $this->assertSame($accepted['senderExpectation']['from'], $postedBody['data']['senderExpectation']['from']);
    }

    // (e) reject posts status:"rejected" and never submits a transaction.
    public function testRejectPostsRejectedStatusWithoutSubmitting(): void
    {
        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        $passphraseKey = KeyHelpers::passphraseKey(self::PASS_PHRASE);
        $rawKp = KeyHelpers::deriveKeypair($mnemonic, '', 0);
        $encrypted = KeyHelpers::encryptKeypair($rawKp['publicKey'], $rawKp['secretKey'], $passphraseKey);
        $mine = new EncryptedKeypairDTO($rawKp['address'], $encrypted['nonce'], $encrypted['save']);

        $offeringPartyAddress = 'd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4';

        $details = [
            'druid' => 'DRUID0xfeedfacefeedfacefeedfacefeedface',
            'senderExpectation' => ['from' => '', 'to' => $offeringPartyAddress, 'asset' => Serialization::assetToken(1000)],
            'receiverExpectation' => ['from' => '', 'to' => $rawKp['address'], 'asset' => Serialization::assetToken(50)],
            'status' => Client::TRANSACTION_STATUS_PENDING,
            'mempoolHost' => self::MEMPOOL_HOST,
        ];

        $client = $this->makeClient([
            $this->jsonResponse([]),
        ]);

        $rejected = $client->reject2WayPayment($details, [$mine]);

        $this->assertSame(Client::TRANSACTION_STATUS_REJECTED, $rejected['status']);

        $this->assertCount(1, $this->lastHistory, 'reject must not submit any transaction, only post to valence');
        $valenceRequest = $this->lastHistory[0]['request'];
        $this->assertSame('POST', $valenceRequest->getMethod());
        $this->assertSame(self::VALENCE_HOST . '/messages', (string) $valenceRequest->getUri());

        $postedBody = json_decode((string) $valenceRequest->getBody(), true);
        $this->assertSame('rejected', $postedBody['data']['status']);
    }

    // (f) a mid-loop mailbox fetch error must not discard already-settled or
    // already-pending results gathered from other mailboxes.
    public function testFetchPendingSurvivesMidLoopMailboxError(): void
    {
        $mnemonic1 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        $mnemonic2 = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

        $passphraseKey = KeyHelpers::passphraseKey(self::PASS_PHRASE);

        $rawKp1 = KeyHelpers::deriveKeypair($mnemonic1, '', 0);
        $encrypted1 = KeyHelpers::encryptKeypair($rawKp1['publicKey'], $rawKp1['secretKey'], $passphraseKey);
        $kp1 = new EncryptedKeypairDTO($rawKp1['address'], $encrypted1['nonce'], $encrypted1['save']);

        $rawKp2 = KeyHelpers::deriveKeypair($mnemonic2, '', 0);
        $encrypted2 = KeyHelpers::encryptKeypair($rawKp2['publicKey'], $rawKp2['secretKey'], $passphraseKey);
        $kp2 = new EncryptedKeypairDTO($rawKp2['address'], $encrypted2['nonce'], $encrypted2['save']);

        $incomingOfferDruid = 'DRUID0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
        $incomingOffer = [
            'druid' => $incomingOfferDruid,
            'senderExpectation' => ['from' => '', 'to' => 'someone-else', 'asset' => Serialization::assetToken(1)],
            'receiverExpectation' => ['from' => '', 'to' => $rawKp1['address'], 'asset' => Serialization::assetToken(1)],
            'status' => Client::TRANSACTION_STATUS_PENDING,
            'mempoolHost' => self::MEMPOOL_HOST,
        ];

        $client = $this->makeClient([
            // Mailbox 1: succeeds, one incoming offer.
            $this->jsonResponse([$incomingOfferDruid => $incomingOffer]),
            // Mailbox 2: fails.
            new Response(500, ['Content-Type' => 'application/json'], json_encode([
                'type' => 'about:blank', 'title' => 'Internal Server Error', 'detail' => 'boom',
            ])),
        ]);

        $result = $client->fetchPending2WayPayment([], [$kp1, $kp2]);

        $this->assertSame([], $result['settled']);
        $this->assertArrayHasKey($incomingOfferDruid, $result['pending']);
        $this->assertSame($incomingOffer, $result['pending'][$incomingOfferDruid]);

        $this->assertCount(2, $this->lastHistory, 'both mailboxes must be attempted despite the second one failing');
    }

    /**
     * No 2-way payment method may still throw NotImplemented.
     */
    public function testTwoWayMethodsExist(): void
    {
        $this->assertTrue(method_exists(Client::class, 'make2WayPayment'));
        $this->assertTrue(method_exists(Client::class, 'fetchPending2WayPayment'));
        $this->assertTrue(method_exists(Client::class, 'accept2WayPayment'));
        $this->assertTrue(method_exists(Client::class, 'reject2WayPayment'));
        $this->assertFalse(method_exists(Client::class, 'createTradeRequest'));
    }
}
