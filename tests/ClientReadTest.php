<?php

declare(strict_types=1);

namespace Lineage\Tests;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Lineage\Client;
use Lineage\Exceptions\LineageApiException;
use PHPUnit\Framework\TestCase;

class ClientReadTest extends TestCase
{
    private const MEMPOOL_HOST = 'https://mempool.example';
    private const STORAGE_HOST = 'https://storage.example';
    private const API_KEY = 'test-api-key';

    private array $lastHistory = [];

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

    public function testFetchBalanceQueriesMempoolWithApiKeyAndBody(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'balance' => [
                    'total' => ['tokens' => 42, 'items' => []],
                    'address_list' => [],
                ],
            ])),
        ]);

        $result = $client->fetchBalance(['addr1', 'addr2']);

        $this->assertCount(1, $this->lastHistory);
        $request = $this->lastHistory[0]['request'];

        $this->assertSame('POST', $request->getMethod());
        $this->assertSame(self::MEMPOOL_HOST . '/v1/balances/query', (string) $request->getUri());
        $this->assertSame(self::API_KEY, $request->getHeaderLine('x-api-key'));
        $this->assertSame(
            ['addresses' => ['addr1', 'addr2']],
            json_decode((string) $request->getBody(), true)
        );

        $this->assertSame(['tokens' => 42, 'items' => []], $result['total']);
    }

    public function testFetchBalanceThrowsLineageApiExceptionOnProblemJson(): void
    {
        $client = $this->makeClient([
            new Response(400, ['Content-Type' => 'application/problem+json'], json_encode([
                'type' => 'https://example.com/errors/bad-request',
                'title' => 'Bad Request',
                'status' => 400,
                'detail' => 'addresses must not be empty',
            ])),
        ]);

        try {
            $client->fetchBalance(['addr1']);
            $this->fail('Expected LineageApiException to be thrown');
        } catch (LineageApiException $e) {
            $this->assertSame(400, $e->getStatus());
            $this->assertSame('Bad Request', $e->getTitle());
            $this->assertSame('addresses must not be empty', $e->getDetail());
            $this->assertSame('https://example.com/errors/bad-request', $e->getType());
        }
    }

    public function testGetSupplyHitsMempoolHost(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'total' => 1000,
                'issued' => 100,
            ])),
        ]);

        $result = $client->getSupply();

        $request = $this->lastHistory[0]['request'];
        $this->assertSame('GET', $request->getMethod());
        $this->assertSame(self::MEMPOOL_HOST . '/v1/supply', (string) $request->getUri());
        $this->assertSame(self::API_KEY, $request->getHeaderLine('x-api-key'));
        $this->assertSame(['total' => 1000, 'issued' => 100], $result);
    }

    public function testGetBlockHitsStorageHostWithBlockNumberInPath(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'key' => 'block-5',
                'item_meta' => ['Block' => 5],
                'data' => [],
            ])),
        ]);

        $result = $client->getBlock(5);

        $request = $this->lastHistory[0]['request'];
        $this->assertSame('GET', $request->getMethod());
        $this->assertSame(self::STORAGE_HOST . '/v1/blocks/5', (string) $request->getUri());
        $this->assertSame('block-5', $result['key']);
    }

    public function testGetLatestBlockHitsStorageHost(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'block' => ['num' => 7],
            ])),
        ]);

        $result = $client->getLatestBlock();

        $request = $this->lastHistory[0]['request'];
        $this->assertSame('GET', $request->getMethod());
        $this->assertSame(self::STORAGE_HOST . '/v1/blocks/latest', (string) $request->getUri());
        $this->assertSame(['num' => 7], $result['block']);
    }

    public function testGetBlockchainEntryHitsStorageHostWithKeyInPath(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'key' => 'some-key',
                'item_meta' => ['Tx' => []],
                'data' => [],
            ])),
        ]);

        $result = $client->getBlockchainEntry('some-key');

        $request = $this->lastHistory[0]['request'];
        $this->assertSame('GET', $request->getMethod());
        $this->assertSame(self::STORAGE_HOST . '/v1/blockchain-entries/some-key', (string) $request->getUri());
        $this->assertSame('some-key', $result['key']);
    }

    public function testGetTransactionStatusQueriesMempoolWithHashesBody(): void
    {
        $client = $this->makeClient([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'deadbeef' => [
                    'status' => 'Confirmed',
                    'timestamp' => 1700000000,
                    'additional_info' => 'in block 5',
                ],
            ])),
        ]);

        $result = $client->getTransactionStatus(['deadbeef']);

        $request = $this->lastHistory[0]['request'];
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame(self::MEMPOOL_HOST . '/v1/transactions/status:query', (string) $request->getUri());
        $this->assertSame(
            ['hashes' => ['deadbeef']],
            json_decode((string) $request->getBody(), true)
        );
        $this->assertSame('Confirmed', $result['deadbeef']['status']);
    }
}
