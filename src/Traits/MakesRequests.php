<?php

declare(strict_types=1);

namespace Lineage\Traits;

use GuzzleHttp\Client as HttpClient;
use Lineage\Exceptions\LineageApiException;
use Lineage\Serialization;

/**
 * MakesRequests is the transport for the /v1 API: a thin, keyless JSON-over-HTTP
 * request helper shared by every read/write method on Client.
 */
trait MakesRequests
{
    final public const GET = 'GET';

    final public const POST = 'POST';

    private ?HttpClient $httpClient = null;

    /**
     * Inject a Guzzle client (e.g. one built on top of a MockHandler stack)
     * in place of the lazily-created default. Intended for tests.
     */
    public function setHttpClient(HttpClient $httpClient): void
    {
        $this->httpClient = $httpClient;
    }

    private function getHttpClient(): HttpClient
    {
        if ($this->httpClient === null) {
            $this->httpClient = new HttpClient();
        }

        return $this->httpClient;
    }

    /**
     * Issue a request against $host . $path on the /v1 API.
     *
     * When $body is non-null it is JSON-encoded (byte-identical to sdk-js's
     * JSON.stringify, via Serialization::json) as the request body and
     * Content-Type is set to application/json. The x-api-key header is sent
     * when the client was configured with an API key.
     *
     * On a non-2xx response, the body is decoded as application/problem+json
     * and thrown as a LineageApiException. On 2xx, the JSON response body is
     * decoded and returned.
     */
    private function request(string $method, string $host, string $path, ?array $body = null): array
    {
        $headers = [];

        if (!empty($this->apiKey)) {
            $headers['x-api-key'] = $this->apiKey;
        }

        $options = [
            'headers' => $headers,
            'http_errors' => false,
        ];

        if ($body !== null) {
            $headers['Content-Type'] = 'application/json';
            $options['headers'] = $headers;
            $options['body'] = Serialization::json($body);
        }

        $response = $this->getHttpClient()->request($method, $host . $path, $options);

        $status = $response->getStatusCode();
        $contents = $response->getBody()->getContents();
        $decoded = $contents !== '' ? json_decode($contents, true) : [];

        if ($status < 200 || $status >= 300) {
            throw LineageApiException::fromResponseBody(is_array($decoded) ? $decoded : [], $status);
        }

        return is_array($decoded) ? $decoded : [];
    }
}
