<?php

namespace Lineage\Tests;

use Lineage\Exceptions\LineageApiException;
use PHPUnit\Framework\TestCase;

class LineageApiExceptionTest extends TestCase
{
    public function testMessagePrefersDetailOverTitle(): void
    {
        $e = LineageApiException::fromResponseBody([
            'type' => 'https://example.com/errors/bad-request',
            'title' => 'Bad Request',
            'detail' => 'script_public_key is required',
        ], 400);

        $this->assertSame('script_public_key is required', $e->getMessage());
        $this->assertSame('Bad Request', $e->getTitle());
        $this->assertSame('https://example.com/errors/bad-request', $e->getType());
        $this->assertSame(400, $e->getStatus());
        $this->assertSame(400, $e->getCode());
    }

    public function testMessageFallsBackToTitleWhenDetailMissing(): void
    {
        $e = LineageApiException::fromResponseBody([
            'title' => 'Not Found',
        ], 404);

        $this->assertSame('Not Found', $e->getMessage());
        $this->assertNull($e->getDetail());
        $this->assertNull($e->getType());
        $this->assertSame(404, $e->getStatus());
    }
}
