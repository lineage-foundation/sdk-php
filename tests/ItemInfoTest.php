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

class ItemInfoTest extends TestCase
{
    private const MEMPOOL_HOST = 'https://mempool.example';
    private const STORAGE_HOST = 'https://storage.example';
    private const API_KEY = 'test-api-key';
    private const GH = 'genesis0abc';

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

    /** JSON 200 response body for the resolver. */
    private static function infoBody(?string $metadata = 'ticket #1'): array
    {
        return [
            'genesis_hash' => self::GH,
            'metadata' => $metadata,
            'total_amount' => 1000,
            'created' => ['block_num' => 42, 'tx_hash' => self::GH],
            'creator_address' => 'addr_creator',
        ];
    }

    private static function jsonResponse(int $status, array $body): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($body));
    }

    /** Count history requests whose path targets the item resolver. */
    private function resolverCallCount(): int
    {
        $count = 0;
        foreach ($this->lastHistory as $entry) {
            if (str_contains($entry['request']->getUri()->getPath(), '/v1/items/')) {
                $count++;
            }
        }

        return $count;
    }

    public function testGetItemInfoResolvesAgainstStorageHost(): void
    {
        $client = $this->makeClient([
            self::jsonResponse(200, self::infoBody()),
        ]);

        $result = $client->getItemInfo(self::GH);

        $request = $this->lastHistory[0]['request'];
        $this->assertSame('GET', $request->getMethod());
        $this->assertSame(self::STORAGE_HOST . '/v1/items/' . self::GH, (string) $request->getUri());
        $this->assertSame(self::API_KEY, $request->getHeaderLine('x-api-key'));
        $this->assertSame(self::infoBody(), $result);
    }

    public function testGetItemInfoCachesSuccessfulResolve(): void
    {
        // Only ONE resolver response is queued; a second HTTP call would
        // exhaust the MockHandler and throw.
        $client = $this->makeClient([
            self::jsonResponse(200, self::infoBody()),
        ]);

        $first = $client->getItemInfo(self::GH);
        $second = $client->getItemInfo(self::GH);

        $this->assertSame(self::infoBody(), $first);
        $this->assertSame(self::infoBody(), $second);
        $this->assertSame(1, $this->resolverCallCount());
    }

    public function testGetItemInfoThrowsOnNotFoundAndDoesNotCache(): void
    {
        $client = $this->makeClient([
            new Response(404, ['Content-Type' => 'application/problem+json'], json_encode([
                'type' => 'https://example.com/errors/not-found',
                'title' => 'Not Found',
                'status' => 404,
                'detail' => 'unknown genesis hash',
            ])),
            // A later success must still hit the network (404 not cached).
            self::jsonResponse(200, self::infoBody()),
        ]);

        try {
            $client->getItemInfo(self::GH);
            $this->fail('Expected LineageApiException to be thrown');
        } catch (LineageApiException $e) {
            $this->assertSame(404, $e->getStatus());
            $this->assertSame('Not Found', $e->getTitle());
        }

        $retried = $client->getItemInfo(self::GH);
        $this->assertSame(self::infoBody(), $retried);
        $this->assertSame(2, $this->resolverCallCount());
    }
}
