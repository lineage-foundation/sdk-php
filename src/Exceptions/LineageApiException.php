<?php

namespace Lineage\Exceptions;

use Exception;

/**
 * LineageApiException wraps an RFC7807-shaped problem-detail error body
 * returned by the /v1 API: {"type","title","status","detail"}.
 */
class LineageApiException extends Exception
{
    public function __construct(
        private ?string $type,
        private ?string $title,
        private int $status,
        private ?string $detail = null,
    ) {
        parent::__construct($detail ?: ($title ?? ''), $status);
    }

    public static function fromResponseBody(array $body, int $status): self
    {
        return new self(
            $body['type'] ?? null,
            $body['title'] ?? null,
            $status,
            $body['detail'] ?? null,
        );
    }

    public function getType(): ?string
    {
        return $this->type;
    }

    public function getTitle(): ?string
    {
        return $this->title;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function getDetail(): ?string
    {
        return $this->detail;
    }
}
