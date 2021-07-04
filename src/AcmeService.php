<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\Http\Client\Response;
use Amp\Promise;
use InvalidArgumentException;
use Kelunik\Acme\Protocol\Account;
use Kelunik\Acme\Protocol\Authorization;
use Kelunik\Acme\Protocol\Challenge;
use Kelunik\Acme\Protocol\ChallengeStatus;
use Kelunik\Acme\Protocol\Order;
use Kelunik\Acme\Protocol\OrderStatus;
use Kelunik\Certificate\Certificate;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface as PsrLogger;
use Psr\Log\NullLogger;
use function Amp\call;
use function Amp\delay;

/**
 * High level ACME client.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class AcmeService
{
    /**
     * @var AcmeClient low level ACME client
     */
    private AcmeClient $client;

    private PsrLogger $logger;

    public function __construct(AcmeClient $client, ?PsrLogger $logger = null)
    {
        $this->client = $client;
        $this->logger = $logger ?? new NullLogger;
    }

    /**
     * Registers a new account on the server.
     *
     * @param string $email e-mail address for contact
     * @param bool   $agreement
     *
     * @return Promise<Account>
     *
     * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.3
     */
    public function register(string $email, bool $agreement = false): Promise
    {
        return call(function () use ($email, $agreement) {
            $this->logger->info('Creating new account with email ' . $email);

            /** @var Response $response */
            $response = yield $this->client->post(AcmeResource::NEW_ACCOUNT, [
                'termsOfServiceAgreed' => $agreement,
                'contact' => [
                    "mailto:{$email}",
                ],
            ]);

            if (\in_array($response->getStatus(), [200, 201], true)) {
                return Account::fromResponse($response->getHeader('location'), yield $response->getBody()->buffer());
            }

            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Retrieves existing order using the order's location URL.
     */
    public function getOrder(UriInterface $url): Promise
    {
        return call(function () use ($url) {
            $this->logger->info('Retrieving order ' . $url);

            /** @var Response $response */
            $response = yield $this->client->post($url, null);

            if ($response->getStatus() === 200) {
                return Order::fromResponse($url, yield $response->getBody()->buffer());
            }

            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Submit a new order for the given DNS names.
     *
     * @param string[]                $domainNames DNS names to request order for
     * @param \DateTimeInterface|null $notBefore The requested value of the notBefore field in the certificate
     * @param \DateTimeInterface|null $notAfter The requested value of the notAfter field in the certificate
     *
     * @return Promise<Order>
     */
    public function newOrder(
        array $domainNames,
        ?\DateTimeInterface $notBefore = null,
        ?\DateTimeInterface $notAfter = null
    ): Promise {
        return call(function () use ($domainNames, $notBefore, $notAfter) {
            $this->logger->info('Creating new order for ' . \implode(', ', $domainNames));

            $request = [
                'identifiers' => [],
            ];

            foreach ($domainNames as $domainName) {
                $request['identifiers'][] = ['type' => 'dns', 'value' => $domainName];
            }

            if ($notBefore) {
                $request['notBefore'] = formatDate($notBefore);
            }

            if ($notAfter) {
                $request['notAfter'] = formatDate($notAfter);
            }

            /** @var Response $response */
            $response = yield $this->client->post(AcmeResource::NEW_ORDER, $request);

            if ($response->getStatus() === 201) {
                return Order::fromResponse($response->getHeader('location'), yield $response->getBody()->buffer());
            }

            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Finalizes a challenge and signals that the CA should validate it.
     *
     * @param UriInterface $url URI of the challenge
     *
     * @return Promise<Challenge>
     */
    public function finalizeChallenge(UriInterface $url): Promise
    {
        return call(function () use ($url) {
            $this->logger->info('Finalizing challenge ' . $url);

            /** @var Response $response */
            $response = yield $this->client->post($url, []);

            try {
                return Challenge::fromResponse(yield $response->getBody()->buffer());
            } catch (\Throwable $_) {
                throw $this->generateException($response, yield $response->getBody()->buffer());
            }
        });
    }

    /**
     * Gets the authorization.
     *
     * @param UriInterface $url
     *
     * @return Promise<Authorization>
     */
    public function getAuthorization(UriInterface $url): Promise
    {
        return call(function () use ($url) {
            $this->logger->info('Retrieving authorization ' . $url);

            /** @var Response $response */
            $response = yield $this->client->post($url, null);

            try {
                return Authorization::fromResponse($url, yield $response->getBody()->buffer());
            } catch (\Throwable $_) {
                throw $this->generateException($response, yield $response->getBody()->buffer());
            }
        });
    }

    /**
     * Gets the challenge.
     *
     * @param UriInterface $url
     *
     * @return Promise<Challenge>
     */
    public function getChallenge(UriInterface $url): Promise
    {
        return call(function () use ($url) {
            $this->logger->info('Retrieving challenge ' . $url);

            /** @var Response $response */
            $response = yield $this->client->post($url, null);

            try {
                return Challenge::fromResponse(yield $response->getBody()->buffer());
            } catch (\Throwable $_) {
                throw $this->generateException($response, yield $response->getBody()->buffer());
            }
        });
    }

    /**
     * Polls until a challenge has been validated.
     *
     * @param UriInterface $url URI of the authorization
     *
     * @return Promise<void>
     */
    public function pollForAuthorization(UriInterface $url): Promise
    {
        return call(function () use ($url) {
            $this->logger->info('Polling for authorization ' . $url);

            do {
                /** @var Authorization $authorization */
                $authorization = yield $this->getAuthorization($url);

                $this->logger->info('Retrieved authorization ' . $url . ': ' . $authorization->getStatus());

                if ($authorization->getStatus() === ChallengeStatus::INVALID) {
                    // TODO Use Challenge->getError
                    throw new AcmeException('Authorization marked as invalid.');
                }

                if ($authorization->getStatus() === ChallengeStatus::VALID) {
                    break;
                }

                yield delay(3000);
            } while (true);
        });
    }

    /**
     * Polls until an order is ready.
     *
     * @param UriInterface $url URI of the order
     *
     * @return Promise<void>
     */
    public function pollForOrderReady(UriInterface $url): Promise
    {
        return call(function () use ($url) {
            $this->logger->info('Polling for order to be ready ' . $url);

            do {
                /** @var Order $order */
                $order = yield $this->getOrder($url);

                $this->logger->info('Retrieved order ' . $url . ': ' . $order->getStatus());

                if ($order->getStatus() === OrderStatus::INVALID) {
                    // TODO Use Challenge->getError
                    throw new AcmeException('Order marked as invalid.');
                }

                if ($order->getStatus() === OrderStatus::READY) {
                    break;
                }

                yield delay(3000);
            } while (true);
        });
    }

    /**
     * Polls until an order is valid.
     *
     * @param UriInterface $url URI of the order
     *
     * @return Promise<void>
     */
    public function pollForOrderValid(UriInterface $url): Promise
    {
        return call(function () use ($url) {
            $this->logger->info('Polling for order to be valid ' . $url);

            do {
                /** @var Order $order */
                $order = yield $this->getOrder($url);

                $this->logger->info('Retrieved order ' . $url . ': ' . $order->getStatus());

                if ($order->getStatus() === OrderStatus::INVALID) {
                    // TODO Use Challenge->getError
                    throw new AcmeException('Order marked as invalid.');
                }

                if ($order->getStatus() === OrderStatus::VALID) {
                    break;
                }

                yield delay(3000);
            } while (true);
        });
    }

    /**
     * Requests a new certificate. This will be done with the finalize URL which is created upon order creation.
     *
     * @param UriInterface $url
     * @param string       $csr certificate signing request
     *
     * @return Promise<Order>
     */
    public function finalizeOrder(UriInterface $url, string $csr): Promise
    {
        return call(function () use ($url, $csr) {
            $this->logger->info('Finalizing order ' . $url);

            $begin = 'REQUEST-----';
            $end = '----END';

            $beginPos = \strpos($csr, $begin);
            if ($beginPos === false) {
                throw new InvalidArgumentException("Invalid CSR, maybe not in PEM format?\n{$csr}");
            }

            $csr = \substr($csr, $beginPos + \strlen($begin));

            $endPos = \strpos($csr, $end);
            if ($endPos === false) {
                throw new InvalidArgumentException("Invalid CSR, maybe not in PEM format?\n{$csr}");
            }

            $csr = \substr($csr, 0, $endPos);

            /** @var Response $response */
            $response = yield $this->client->post($url, [
                'csr' => base64UrlEncode(\base64_decode($csr)),
            ]);

            if ($response->getStatus() === 200) {
                return Order::fromResponse($response->getHeader('location'), yield $response->getBody()->buffer());
            }

            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Downloads the certificate (and parent certificates).
     *
     * @param UriInterface $url URI of the certificate
     *
     * @return Promise Complete certificate chain as array of PEM encoded certificates
     */
    public function downloadCertificates(UriInterface $url): Promise
    {
        return call(function () use ($url) {
            $this->logger->info('Downloading certificate ' . $url);

            /** @var Response $response */
            $response = yield $this->client->post($url, null);

            if ($response->getStatus() === 200) {
                $certificateChain = yield $response->getBody()->buffer();
                $certificates = [];

                while (\preg_match(
                    '(-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----)si',
                    $certificateChain,
                    $match
                )) {
                    $certificateChain = \str_replace($match[0], '', $certificateChain);
                    $certificate = Certificate::derToPem(Certificate::pemToDer($match[0]));

                    $certificates[] = $certificate;
                }

                return $certificates;
            }

            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Revokes a certificate.
     *
     * @param string $pem PEM encoded certificate
     *
     * @return Promise<void>
     */
    public function revokeCertificate(string $pem): Promise
    {
        return call(function () use ($pem) {
            $this->logger->info('Revoking certificate ' . $pem);

            /** @var Response $response */
            $response = yield $this->client->post(AcmeResource::REVOKE_CERTIFICATE, [
                'certificate' => base64UrlEncode(Certificate::pemToDer($pem)),
            ]);

            if ($response->getStatus() === 200) {
                return;
            }

            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Parses a retry header into seconds to wait until a request should be retried.
     *
     * @param string $header header value
     *
     * @return int seconds to wait until retry
     * @throws AcmeException If the header value cannot be parsed.
     */
    private function parseRetryAfter(string $header): int
    {
        if (\preg_match('#^\d+$#', $header)) {
            return (int) $header;
        }

        $time = @\strtotime($header);

        if ($time === false) {
            throw new AcmeException("Invalid retry-after header: '{$header}'");
        }

        return \max($time - \time(), 0);
    }

    /**
     * Generates a new exception using the response to provide details.
     *
     * @param Response $response HTTP response to generate the exception from.
     * @param string   $body HTTP response body.
     *
     * @return AcmeException exception generated from the response body
     */
    private function generateException(Response $response, string $body): AcmeException
    {
        $status = $response->getStatus();
        $info = \json_decode($body);
        $uri = $response->getRequest()->getUri();

        if (isset($info->type, $info->detail)) {
            return new AcmeException("Invalid response: {$info->detail}.\nRequest URI: {$uri}.", $info->type);
        }

        return new AcmeException("Invalid response: {$body}.\nRequest URI: {$uri}.", $status);
    }
}
