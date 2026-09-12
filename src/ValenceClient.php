<?php

declare(strict_types=1);

namespace Lineage;

use GuzzleHttp\Client as HttpClient;
use Lineage\Exceptions\LineageApiException;

/**
 * ValenceClient is a client for a valence mailbox host: the plaintext
 * message-relay service two-way payment counterparties use to exchange
 * DRUID trade offers, acceptances, and rejections. Messages are sent and
 * stored in plaintext — valence provides delivery and mailbox scoping, not
 * confidentiality. Every request is authenticated by signing the target
 * mailbox address's raw bytes with the caller's own keypair (see
 * authHeaders), matching sdk-js's generateVerificationHeaders / sdk-go's
 * valenceAuthHeaders.
 */
class ValenceClient
{
    private const MESSAGES_PATH = '/messages';

    public function __construct(
        private string $host,
        private ?HttpClient $httpClient = null,
    ) {
    }

    private function getHttpClient(): HttpClient
    {
        if ($this->httpClient === null) {
            $this->httpClient = new HttpClient();
        }

        return $this->httpClient;
    }

    /**
     * Places (or overwrites) the plaintext offer/status $details under the
     * mailbox identified by $address ($details['druid'] is the mailbox
     * entry's id), signed by $keyPair. Mirrors sdk-js's `POST /messages`
     * (IAPIRoute.ValenceSet) call in make2WayPayment / handle2WTxResponse.
     *
     * @param array{publicKey:string,secretKey:string} $keyPair
     * @param array $details A Pending2WTxDetails-shaped array:
     *   {druid,senderExpectation,receiverExpectation,status,mempoolHost}.
     */
    public function post(string $address, array $keyPair, array $details): void
    {
        $this->request(
            method: 'POST',
            path: self::MESSAGES_PATH,
            address: $address,
            keyPair: $keyPair,
            body: [
                'id' => $details['druid'],
                'data' => $details,
            ],
        );
    }

    /**
     * Returns the full contents of $address's mailbox: a map of druid to
     * the stored Pending2WTxDetails payload, directly (not wrapped), signed
     * by $keyPair. Mirrors sdk-js's `GET /messages` (IAPIRoute.ValenceGet)
     * call in fetchPending2WayPayment.
     *
     * @param array{publicKey:string,secretKey:string} $keyPair
     */
    public function get(string $address, array $keyPair): array
    {
        return $this->request(
            method: 'GET',
            path: self::MESSAGES_PATH,
            address: $address,
            keyPair: $keyPair,
        );
    }

    /**
     * Removes the mailbox entry identified by $druid from $address's
     * mailbox, signed by $keyPair. Mirrors sdk-js's `DELETE /messages/{id}`
     * (IAPIRoute.ValenceDel) call in fetchPending2WayPayment.
     *
     * @param array{publicKey:string,secretKey:string} $keyPair
     */
    public function delete(string $druid, string $address, array $keyPair): void
    {
        $this->request(
            method: 'DELETE',
            path: self::MESSAGES_PATH . '/' . rawurlencode($druid),
            address: $address,
            keyPair: $keyPair,
        );
    }

    /**
     * Issue an authenticated request against $this->host . $path, signing
     * with $address/$keyPair per authHeaders. When $body is non-null it is
     * JSON-encoded as the request body. On a non-2xx response the body is
     * decoded as application/problem+json and thrown as a
     * LineageApiException; on 2xx, the JSON response body is decoded and
     * returned.
     *
     * @param array{publicKey:string,secretKey:string} $keyPair
     */
    private function request(string $method, string $path, string $address, array $keyPair, ?array $body = null): array
    {
        $headers = $this->authHeaders($address, $keyPair);

        $options = [
            'headers' => $headers,
            'http_errors' => false,
        ];

        if ($body !== null) {
            $headers['Content-Type'] = 'application/json';
            $options['headers'] = $headers;
            $options['body'] = Serialization::json($body);
        }

        $response = $this->getHttpClient()->request($method, $this->host . $path, $options);

        $status = $response->getStatusCode();
        $contents = $response->getBody()->getContents();
        $decoded = $contents !== '' ? json_decode($contents, true) : [];

        if ($status < 200 || $status >= 300) {
            throw LineageApiException::fromResponseBody(is_array($decoded) ? $decoded : [], $status);
        }

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * The address/public_key/signature headers a valence request must
     * carry: address is the target mailbox's address (hex), public_key is
     * the caller's own public key (hex), and signature is a detached
     * ed25519 signature over the mailbox address string's raw UTF-8 bytes
     * (unhashed). The signing keypair need not be the mailbox address's own
     * keypair: valence messages may be posted into (or deleted from) a
     * counterparty's mailbox, signed by the sender's own key, as proof of a
     * validly-held keypair rather than of mailbox ownership.
     *
     * @param array{publicKey:string,secretKey:string} $keyPair
     */
    private function authHeaders(string $address, array $keyPair): array
    {
        $signature = sodium_crypto_sign_detached($address, $keyPair['secretKey']);

        return [
            'address' => $address,
            'public_key' => sodium_bin2hex($keyPair['publicKey']),
            'signature' => sodium_bin2hex($signature),
        ];
    }
}
