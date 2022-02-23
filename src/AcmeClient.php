<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\ByteStream\ReadableBuffer;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Interceptor\AddRequestHeader;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Kelunik\Acme\Crypto\Backend\Backend;
use Kelunik\Acme\Crypto\Backend\OpensslBackend;
use Kelunik\Acme\Crypto\PrivateKey;
use Kelunik\Acme\Protocol\Account;
use Psr\Log\LoggerInterface as PsrLogger;
use Psr\Log\NullLogger;
use Throwable;
use function Amp\delay;
use function Sabre\Uri\resolve;

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
    private HttpClient $httpClient;

    /**
     * @var Backend Crypto backend.
     */
    private Backend $cryptoBackend;

    /**
     * @var PrivateKey Account key.
     */
    private PrivateKey $accountKey;

    /**
     * @var string|null Account location URI
     */
    private ?string $accountUrl = null;

    /**
     * @var string Directory URI of the ACME server.
     */
    private string $directoryUrl;

    /**
     * @var array Directory contents of the ACME server.
     */
    private array $directory = [];

    /**
     * @var string[] Cached nonces for use in future requests.
     */
    private array $nonces;

    /**
     * @var PsrLogger Logger for debug information.
     */
    private PsrLogger $logger;

    /**
     * AcmeClient constructor.
     *
     * @param string          $directoryUri URI to the ACME server directory.
     * @param PrivateKey      $accountKey Account key.
     * @param HttpClient|null $httpClient Custom HTTP client, a default client will be used if no value is provided.
     * @param Backend|null    $cryptoBackend Custom crypto backend, a default OpensslBackend will be used if no value is
     *     provided.
     * @param PsrLogger|null  $logger Logger for debug information.
     */
    public function __construct(
        string $directoryUri,
        PrivateKey $accountKey,
        ?HttpClient $httpClient = null,
        ?Backend $cryptoBackend = null,
        ?PsrLogger $logger = null
    ) {
        $this->directoryUrl = $directoryUri;
        $this->accountKey = $accountKey;
        $this->httpClient = $httpClient ?? $this->buildClient();
        $this->cryptoBackend = $cryptoBackend ?? new OpensslBackend;
        $this->logger = $logger ?? new NullLogger;
        $this->nonces = [];
    }

    /**
     * Retrieves a resource using a GET request.
     *
     * @param string $resource Resource to fetch.
     *
     * @return Response Resolves to the HTTP response.
     */
    public function get(string $resource): Response
    {
            $url = $this->getResourceUrl($resource);

            $this->logger->debug('Requesting {url} via GET', [
                'url' => $url,
            ]);

            try {
                $response = $this->httpClient->request(new Request($url));

                // We just buffer the body here, so no further I/O will happen once this method's promise resolves.
                $body = $response->getBody()->buffer();
                $response->setBody(new ReadableBuffer($body));

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
    }

    /**
     * Retrieves a resource using a POST request.
     *
     * @param string     $resource Resource to fetch.
     * @param array|null $payload Payload as associative array to send.
     *
     * @return Response Resolves to the HTTP response.
     */
    public function post(string $resource, ?array $payload): Response
    {
        $url = $this->getResourceUrl($resource);

        $newAccountUrl = $this->getResourceUrl(AcmeResource::NEW_ACCOUNT);

        $attempt = 0;
        $statusCode = null;

        do {
            $attempt++;

            if ($attempt > 3) {
                throw new AcmeException("POST request to {$url} failed, received too many errors (last code: ${statusCode}).");
            }

            $accountUrl = $url === $newAccountUrl ? null : $this->accountUrl;
            if ($url !== $newAccountUrl && $this->accountUrl === null) {
                $account = $this->getAccount();
                $this->accountUrl = $accountUrl = (string) $account->getUrl();
            }

            $requestBody = $this->cryptoBackend->signJwt(
                $this->accountKey,
                $url,
                $this->getNonce(),
                $payload,
                $accountUrl
            );

            $request = new Request($url, 'POST', $requestBody);

            $this->logger->debug('Requesting {url} via POST: {body}', [
                'url' => $url,
                'body' => $requestBody,
            ]);

            try {
                if ($request->getMethod() === 'POST') {
                    $request->setHeader('content-type', 'application/jose+json');
                }

                $response = $this->httpClient->request($request);
                $statusCode = $response->getStatus();
                $body = $response->getBody()->buffer();
                $response->setBody(new ReadableBuffer($body));

                $this->logger->debug('Request for {url} via POST has been processed with status {status}: {body}', [
                    'url' => $url,
                    'status' => $statusCode,
                    'body' => $body,
                ]);

                $this->saveNonce($response);

                if ($statusCode === 400) {
                    $info = \json_decode($body, true, 16, \JSON_THROW_ON_ERROR);

                    if (!empty($info['type']) && (\strpos($info['type'], "acme:error:badNonce") !== false)) {
                        $this->nonces = [];
                        continue;
                    }
                } elseif ($statusCode === 429) {
                    /**
                     * Hit rate limit.
                     * @{link} https://letsencrypt.org/docs/rate-limits/
                     */
                    delay(1000);
                    continue;
                }
            } catch (Throwable $e) {
                throw new AcmeException("POST request to {$url} failed: " . $e->getMessage(), null, $e);
            }

            return $response;
        } while (true);
    }

    /**
     * Constructs the default HTTP client.
     */
    private function buildClient(): HttpClient
    {
        return (new HttpClientBuilder)
            ->intercept(new AddRequestHeader('user-agent', 'kelunik/acme'))
            ->build();
    }

    /**
     * Pops a locally stored nonce or requests a new one for usage.
     *
     * @return string Resolves to a valid nonce.
     */
    private function getNonce(): string
    {
        if (empty($this->nonces)) {
            return $this->requestNonce();
        }

        return \array_shift($this->nonces);
    }

    private function getAccount(): Account
    {
        $response = $this->post(AcmeResource::NEW_ACCOUNT, [
            'onlyReturnExisting' => true,
        ]);

        if (\in_array($response->getStatus(), [200, 201], true)) {
            return Account::fromResponse($response->getHeader('location'), $response->getBody()->buffer());
        }

        throw new AcmeException('Unable to find account with given private key');
    }

    /**
     * Requests a new request nonce from the server.
     *
     * @return string Resolves to a valid nonce.
     */
    private function requestNonce(): string
    {
            $url = $this->getResourceUrl(AcmeResource::NEW_NONCE);
            $request = new Request($url, 'HEAD');

            try {
                $response = $this->httpClient->request($request);

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
    }

    /**
     * Returns the URI to a resource by querying the directory. Can also handle URIs and returns them directly.
     *
     * @param string $resource URI or directory entry.
     *
     * @return string Resolves to the resource URI.
     */
    private function getResourceUrl(string $resource): string
    {
        // ACME MUST be served over HTTPS, but we use HTTP for testing …
        if (0 === \strpos($resource, 'http://') || 0 === \strpos($resource, 'https://')) {
            return $resource;
        }

        if (!$this->directory) {
                $this->fetchDirectory();

                return $this->getResourceUrl($resource);
        }

        if (isset($this->directory[$resource])) {
            return $this->directory[$resource];
        }

        throw new AcmeException("Resource not found in directory: '{$resource}'.");
    }

    /**
     * Retrieves the directory and stores it in the directory property.
     *
     * @return void Resolves once the directory is fetched.
     */
    private function fetchDirectory(): void
    {
        try {
            $this->logger->debug('Fetching directory from {url}', [
                'url' => $this->directoryUrl,
            ]);

            $response = $this->httpClient->request(new Request($this->directoryUrl));
            $directory = \json_decode($response->getBody()->buffer(), true);

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

            foreach (AcmeResource::getAll() as $key) {
                if (isset($directory[$key])) {
                    $directory[$key] = resolve($this->directoryUrl, $directory[$key]);
                }
            }

            $this->directory = $directory;
            $this->saveNonce($response);
        } catch (Throwable $e) {
            throw new AcmeException('Could not obtain directory: ' . $e->getMessage(), null, $e);
        }
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
