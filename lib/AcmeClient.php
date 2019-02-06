<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\DefaultClient;
use Amp\Artax\HttpException;
use Amp\Artax\Request;
use Amp\Artax\Response;
use Amp\Delayed;
use Amp\Failure;
use Amp\Promise;
use Amp\Success;
use Exception;
use Kelunik\Acme\Crypto\Backend\Backend;
use Kelunik\Acme\Crypto\Backend\OpensslBackend;
use Kelunik\Acme\Crypto\PrivateKey;
use Psr\Log\LoggerInterface as PsrLogger;
use Psr\Log\NullLogger;
use Throwable;
use function Amp\call;

/**
 * Low level ACME client.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
final class AcmeClient {
    /**
     * @var Client HTTP client.
     */
    private $http;

    /**
     * @var Backend Crypto backend.
     */
    private $cryptoBackend;

    /**
     * @var PrivateKey Account key.
     */
    private $accountKey;

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
     * @api
     *
     * @param string         $directoryUri URI to the ACME server directory.
     * @param PrivateKey     $accountKey Account key.
     * @param Client|null    $http Custom HTTP client, a default client will be used if no value is provided.
     * @param Backend|null   $cryptoBackend Custom crypto backend, a default OpensslBackend will be used if no value is
     *                                      provided.
     * @param PsrLogger|null $logger Logger for debug information.
     */
    public function __construct(string $directoryUri, PrivateKey $accountKey, Client $http = null, Backend $cryptoBackend = null, PsrLogger $logger = null) {
        $this->directoryUri = $directoryUri;
        $this->accountKey = $accountKey;
        $this->http = $http ?? $this->buildClient();
        $this->cryptoBackend = $cryptoBackend ?? new OpensslBackend;
        $this->nonces = [];
        $this->logger = $logger ?? new NullLogger;
    }

    /**
     * Constructs the default HTTP client.
     *
     * @return Client
     */
    private function buildClient(): Client {
        $client = new DefaultClient;
        $client->setOption(Client::OP_DEFAULT_HEADERS, [
            'user-agent' => 'kelunik/acme',
        ]);

        return $client;
    }

    /**
     * Pops a locally stored nonce or requests a new one for usage.
     *
     * @param string $uri URI to issue the HEAD request against if no nonce is stored locally.
     *
     * @return Promise Resolves to a valid nonce.
     */
    private function getNonce(string $uri): Promise {
        if (empty($this->nonces)) {
            return $this->requestNonce($uri);
        }

        return new Success(array_shift($this->nonces));
    }

    /**
     * Requests a new request nonce from the server.
     *
     * @param string $uri URI to issue the HEAD request against.
     *
     * @return Promise Resolves to a valid nonce.
     */
    private function requestNonce(string $uri): Promise {
        return call(function () use ($uri) {
            $request = new Request($uri, 'HEAD');

            try {
                /** @var Response $response */
                $response = yield $this->http->request($request, [
                    Client::OP_DISCARD_BODY => true,
                ]);

                if (!$response->hasHeader('replay-nonce')) {
                    throw new AcmeException("HTTP response didn't carry replay-nonce header.");
                }

                return $response->getHeader('replay-nonce');
            } catch (HttpException $e) {
                throw new AcmeException("HEAD request to {$uri} failed, could not obtain a replay nonce: " . $e->getMessage(), null, $e);
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
    private function getResourceUri(string $resource): Promise {
        // ACME MUST be served over HTTPS, but we use HTTP for testing …
        if (0 === strpos($resource, 'http://') || 0 === strpos($resource, 'https://')) {
            return new Success($resource);
        }

        if (!$this->directory) {
            return call(function () use ($resource) {
                yield $this->fetchDirectory();

                return $this->getResourceUri($resource);
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
    private function fetchDirectory(): Promise {
        return call(function () {
            try {
                $this->logger->debug('Fetching directory from {uri}', [
                    'uri' => $this->directoryUri
                ]);

                /** @var Response $response */
                $response = yield $this->http->request($this->directoryUri);
                $directory = json_decode(yield $response->getBody(), true);

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
     * Retrieves a resource using a GET request.
     *
     * @api
     *
     * @param string $resource Resource to fetch.
     *
     * @return Promise Resolves to the HTTP response.
     * @throws AcmeException If the request failed.
     */
    public function get(string $resource): Promise {
        return call(function () use ($resource) {
            $uri = yield $this->getResourceUri($resource);

            $this->logger->debug('Requesting {uri} via GET', [
                'uri' => $uri,
            ]);

            try {
                /** @var Response $response */
                $response = yield $this->http->request($uri);

                // We just buffer the body here, so no further I/O will happen once this method's promise resolves.
                $body = yield $response->getBody();

                $this->logger->debug('Request for {uri} via GET has been processed with status {status}: {body}', [
                    'uri' => $uri,
                    'status' => $response->getStatus(),
                    'body' => $body
                ]);

                $this->saveNonce($response);
            } catch (Throwable $e) {
                throw new AcmeException("GET request to {$uri} failed: " . $e->getMessage(), null, $e);
            } catch (Exception $e) {
                throw new AcmeException("GET request to {$uri} failed: " . $e->getMessage(), null, $e);
            }

            return $response;
        });
    }

    /**
     * Retrieves a resource using a POST request.
     *
     * @api
     *
     * @param string $resource Resource to fetch.
     * @param array  $payload Payload as associative array to send.
     *
     * @return Promise Resolves to the HTTP response.
     * @throws AcmeException If the request failed.
     */
    public function post(string $resource, array $payload): Promise {
        return call(function () use ($resource, $payload) {
            $uri = yield $this->getResourceUri($resource);

            $attempt = 0;
            $statusCode = null;

            do {
                $attempt++;

                if ($attempt > 3) {
                    throw new AcmeException("POST request to {$uri} failed, received too many errors (last code: ${statusCode}).");
                }

                $payload['resource'] = $payload['resource'] ?? $resource;

                $requestBody = $this->cryptoBackend->signJwt($this->accountKey, yield $this->getNonce($uri), $payload);
                $request = (new Request($uri, 'POST'))
                    ->withBody($requestBody);

                $this->logger->debug('Requesting {uri} via POST: {body}', [
                    'uri' => $uri,
                    'body' => $requestBody,
                ]);

                try {
                    /** @var Response $response */
                    $response = yield $this->http->request($request);
                    $statusCode = $response->getStatus();
                    $body = yield $response->getBody();

                    $this->logger->debug('Request for {uri} via POST has been processed with status {status}: {body}', [
                        'uri' => $uri,
                        'status' => $statusCode,
                        'body' => $body
                    ]);

                    $this->saveNonce($response);

                    if ($statusCode === 400) {
                        $info = json_decode($body);

                        if (!empty($info->type) && ($info->type === 'urn:acme:badNonce' || $info->type === 'urn:acme:error:badNonce')) {
                            $this->nonces = [];
                            continue;
                        }
                    } else if ($statusCode === 429) {
                        /**
                         * Hit rate limit
                         * @{link} https://letsencrypt.org/docs/rate-limits/
                         */
                        yield new Delayed(1000);
                        continue;
                    }
                } catch (Throwable $e) {
                    throw new AcmeException("POST request to {$uri} failed: " . $e->getMessage(), null, $e);
                } catch (Exception $e) {
                    throw new AcmeException("POST request to {$uri} failed: " . $e->getMessage(), null, $e);
                }

                return $response;
            } while (true);
        });
    }

    /**
     * Saves the nonce if one was provided in the response.
     *
     * @param Response $response Response which may carry a new replay nonce as header.
     */
    private function saveNonce(Response $response) {
        if (!$response->hasHeader('replay-nonce')) {
            return;
        }

        $this->nonces[] = $response->getHeader('replay-nonce');
    }
}
