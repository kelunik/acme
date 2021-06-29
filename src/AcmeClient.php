<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\Failure;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Interceptor\AddRequestHeader;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\Promise;
use Amp\Success;
use Kelunik\Acme\Crypto\Backend\Backend;
use Kelunik\Acme\Crypto\Backend\OpensslBackend;
use Kelunik\Acme\Crypto\PrivateKey;
use Psr\Log\LoggerInterface as PsrLogger;
use Psr\Log\NullLogger;
use Throwable;
use function Amp\call;
use function Amp\delay;

/**
 * Low level ACME client.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
final class AcmeClient
{
    /**
     * @var HttpClient HTTP client.
     */
    private $httpClient;

    /**
     * @var Backend Crypto backend.
     */
    private $cryptoBackend;

    /**
     * @var PrivateKey Account key.
     */
    private $accountKey;

    /**
     * @var string Account location URI
     */
    private $accountLocation;

    /**
     * @var string Directory URI of the ACME server.
     */
    private $directoryUri;

    /**
     * @var array Directory contents of the ACME server.
     */
    private $directory;

    /**
     * @var array Cached nonces for use in future requests.
     */
    private $nonces;

    /**
     * @var PsrLogger Logger for debug information.
     */
    private $logger;

    /**
     * AcmeClient constructor.
     *
     * @param string          $directoryUri URI to the ACME server directory.
     * @param string|null     $accountLocation
     * @param PrivateKey      $accountKey Account key.
     * @param HttpClient|null $httpClient Custom HTTP client, a default client will be used if no value is provided.
     * @param Backend|null    $cryptoBackend Custom crypto backend, a default OpensslBackend will be used if no value is
     *     provided.
     * @param PsrLogger|null  $logger Logger for debug information.
     *
     * @api
     */
    public function __construct(
        string $directoryUri,
        PrivateKey $accountKey,
        ?string $accountLocation = null,
        ?HttpClient $httpClient = null,
        ?Backend $cryptoBackend = null,
        ?PsrLogger $logger = null
    ) {
        $this->directoryUri = $directoryUri;
        $this->accountKey = $accountKey;
        $this->accountLocation = $accountLocation;
        $this->httpClient = $httpClient ?? $this->buildClient();
        $this->cryptoBackend = $cryptoBackend ?? new OpensslBackend;
        $this->nonces = [];
        $this->logger = $logger ?? new NullLogger;
    }

    /**
     * Retrieves a resource using a GET request.
     *
     * @param string $resource Resource to fetch.
     *
     * @return Promise Resolves to the HTTP response.
     * @throws AcmeException If the request failed.
     * @api
     */
    public function get(string $resource): Promise
    {
        return call(function () use ($resource) {
            $url = yield $this->getResourceUrl($resource);

            $this->logger->debug('Requesting {url} via GET', [
                'url' => $url,
            ]);

            try {
                /** @var Response $response */
                $response = yield $this->httpClient->request($url);

                // We just buffer the body here, so no further I/O will happen once this method's promise resolves.
                $body = yield $response->getBody();

                $this->logger->debug('Request for {url} via GET has been processed with status {status}: {body}', [
                    'url' => $url,
                    'status' => $response->getStatus(),
                    'body' => $body,
                ]);

                $this->saveNonce($response);
            } catch (Throwable $e) {
                throw new AcmeException("GET request to {$url} failed: " . $e->getMessage(), null, $e);
            }

            return $response;
        });
    }

    /**
     * Retrieves a resource using a POST request.
     *
     * @param string $resource Resource to fetch.
     * @param array  $payload Payload as associative array to send.
     *
     * @return Promise Resolves to the HTTP response.
     * @throws AcmeException If the request failed.
     * @api
     */
    public function post(string $resource, array $payload): Promise
    {
        return call(function () use ($resource, $payload) {
            $url = yield $this->getResourceUrl($resource);

            $attempt = 0;
            $statusCode = null;

            do {
                $attempt++;

                if ($attempt > 3) {
                    throw new AcmeException("POST request to {$url} failed, received too many errors (last code: ${statusCode}).");
                }

                $payload['url'] = $payload['url'] ?? $url;

                $accountLocation = AcmeResource::requiresJwkAuthorization($resource) ? null : $this->accountLocation;
                $requestBody = $this->cryptoBackend->signJwt(
                    $this->accountKey,
                    yield $this->getNonce(),
                    $payload,
                    $accountLocation
                );
                $request = new Request($url, 'POST', $requestBody);

                $this->logger->debug('Requesting {url} via POST: {body}', [
                    'url' => $url,
                    'body' => $requestBody,
                ]);

                try {
                    /** @var Response $response */
                    $response = yield $this->httpClient->request($request);
                    $statusCode = $response->getStatus();
                    $body = yield $response->getBody()->buffer();

                    $this->logger->debug('Request for {url} via POST has been processed with status {status}: {body}', [
                        'url' => $url,
                        'status' => $statusCode,
                        'body' => $body,
                    ]);

                    $this->saveNonce($response);

                    if ($statusCode === 400) {
                        $info = \json_decode($body, true);

                        if (!empty($info['type']) && (\strpos($info['type'], "acme:error:badNonce") !== false)) {
                            $this->nonces = [];
                            continue;
                        }
                    } elseif ($statusCode === 429) {
                        /**
                         * Hit rate limit.
                         * @{link} https://letsencrypt.org/docs/rate-limits/
                         */
                        yield delay(1000);
                        continue;
                    }
                } catch (Throwable $e) {
                    throw new AcmeException("POST request to {$url} failed: " . $e->getMessage(), null, $e);
                }

                return $response;
            } while (true);
        });
    }

    /**
     * Constructs the default HTTP client.
     */
    private function buildClient(): HttpClient
    {
        return (new HttpClientBuilder)
            ->intercept(new AddRequestHeader('user-agent', 'kelunik/acme'))
            ->intercept(new AddRequestHeader('content-type', 'application/jose+json'))
            ->build();
    }

    /**
     * Pops a locally stored nonce or requests a new one for usage.
     *
     * @return Promise<string> Resolves to a valid nonce.
     */
    private function getNonce(): Promise
    {
        if (empty($this->nonces)) {
            return $this->requestNonce();
        }

        return new Success(\array_shift($this->nonces));
    }

    /**
     * Requests a new request nonce from the server.
     *
     * @return Promise Resolves to a valid nonce.
     */
    private function requestNonce(): Promise
    {
        return call(function () {
            $url = yield $this->getResourceUrl(AcmeResource::NEW_NONCE);
            $request = new Request($url, 'HEAD');

            try {
                /** @var Response $response */
                $response = yield $this->httpClient->request($request);

                if (!$response->hasHeader('replay-nonce')) {
                    throw new AcmeException("HTTP response didn't carry replay-nonce header.");
                }

                return $response->getHeader('replay-nonce');
            } catch (HttpException $e) {
                throw new AcmeException(
                    "HEAD request to {$url} failed, could not obtain a replay nonce: " . $e->getMessage(),
                    null,
                    $e
                );
            }
        });
    }

    /**
     * Returns the URI to a resource by querying the directory. Can also handle URIs and returns them directly.
     *
     * @param string $resource URI or directory entry.
     *
     * @return Promise Resolves to the resource URI.
     * @throws AcmeException If the specified resource is not in the directory.
     */
    private function getResourceUrl(string $resource): Promise
    {
        // ACME MUST be served over HTTPS, but we use HTTP for testing …
        if (0 === \strpos($resource, 'http://') || 0 === \strpos($resource, 'https://')) {
            return new Success($resource);
        }

        if (!$this->directory) {
            return call(function () use ($resource) {
                yield $this->fetchDirectory();

                return $this->getResourceUrl($resource);
            });
        }

        if (isset($this->directory[$resource])) {
            return new Success($this->directory[$resource]);
        }

        return new Failure(new AcmeException("Resource not found in directory: '{$resource}'."));
    }

    /**
     * Retrieves the directory and stores it in the directory property.
     *
     * @return Promise Resolves once the directory is fetched.
     * @throws AcmeException If the directory could not be fetched or was invalid.
     */
    private function fetchDirectory(): Promise
    {
        return call(function () {
            try {
                $this->logger->debug('Fetching directory from {url}', [
                    'url' => $this->directoryUri,
                ]);

                /** @var Response $response */
                $response = yield $this->httpClient->request(new Request($this->directoryUri));
                $directory = \json_decode(yield $response->getBody()->buffer(), true);

                if ($response->getStatus() !== 200) {
                    $error = $directory;

                    if (isset($error['type'], $error['detail'])) {
                        throw new AcmeException("Invalid directory response: {$error['detail']}", $error['type']);
                    }

                    throw new AcmeException('Invalid directory response. HTTP response code: ' . $response->getStatus());
                }

                if (empty($directory)) {
                    throw new AcmeException('Invalid empty directory.');
                }

                $this->directory = $directory;
                $this->saveNonce($response);
            } catch (Throwable $e) {
                throw new AcmeException('Could not obtain directory: ' . $e->getMessage(), null, $e);
            }
        });
    }

    /**
     * Saves the nonce if one was provided in the response.
     *
     * @param Response $response Response which may carry a new replay nonce as header.
     */
    private function saveNonce(Response $response): void
    {
        if (!$response->hasHeader('replay-nonce')) {
            return;
        }

        $this->nonces[] = $response->getHeader('replay-nonce');
    }
}
