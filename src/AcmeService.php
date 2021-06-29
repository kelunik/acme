<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\Delayed;
use Amp\Http\Client\Response;
use Amp\Promise;
use InvalidArgumentException;
use Kelunik\Acme\Domain\Authorization;
use Kelunik\Acme\Domain\Challenge;
use Kelunik\Acme\Domain\Order;
use Kelunik\Acme\Domain\Registration;
use Kelunik\Certificate\Certificate;
use function Amp\call;
use function Sabre\Uri\resolve;

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
    private $acmeClient;

    /**
     * AcmeService constructor.
     *
     * @param AcmeClient $acmeClient ACME client
     *
     * @api
     */
    public function __construct(AcmeClient $acmeClient)
    {
        $this->acmeClient = $acmeClient;
    }

    /**
     * Registers a new account on the server.
     *
     * @param string $email e-mail address for contact
     * @param bool   $agreement
     *
     * @return Promise resolves to a Registration object
     * @throws AcmeException If something went wrong.
     *
     * @api
     */
    public function register(string $email, bool $agreement = false): Promise
    {
        return call(function () use ($email, $agreement) {
            $payload = [
                'termsOfServiceAgreed' => $agreement,
                'contact' => [
                    "mailto:{$email}",
                ],
            ];

            /** @var Response $response */
            $response = yield $this->acmeClient->post(AcmeResource::NEW_ACCOUNT, $payload);

            if (\in_array($response->getStatus(), [200, 201])) {
                if (!$response->hasHeader('location')) {
                    throw new AcmeException('Protocol Violation: No Location Header');
                }

                $location = $response->getHeader('location');

                $payload = \json_decode(yield $response->getBody()->buffer());

                if ($response->hasHeader('link')) {
                    $links = $response->getHeaderArray('link');

                    foreach ($links as $link) {
                        if (\preg_match('#<(.*?)>;rel="terms-of-service"#x', $link, $match)) {
                            $uri = resolve($response->getRequest()->getUri(), $match[1]);
                            return $this->register($email, $uri);
                        }
                    }
                }
                return new Registration($location, $payload->status, $payload->contact, $payload->orders ?? null);
            }

            if ($response->getStatus() === 409) {
                if (!$response->hasHeader('location')) {
                    throw new AcmeException("Protocol violation: 409 Conflict. Response didn't carry any location header.");
                }
                $location = $response->getHeader('location');

                $payload = [
                    'termsOfServiceAgreed' => $agreement,
                    'contact' => [
                        "mailto:{$email}",
                    ],
                ];

                $response = yield $this->acmeClient->post($location, $payload);
                $payload = \json_decode(yield $response->getBody()->buffer());

                return new Registration($location, $payload->status, $payload->contact, $payload->orders ?? null);
            }

            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Retrieves existing order using the order's location URL.
     *
     * @param string $location
     *
     * @return Promise
     */
    public function getOrder(string $location): Promise
    {
        return call(function () use ($location) {
            /** @var Response $response */
            $response = yield $this->acmeClient->post($location, []);

            if (\in_array($response->getStatus(), [200, 201])) {
                $payload = \json_decode(yield $response->getBody()->buffer());
                $payload->location = $location;
                return Order::fromResponse($payload);
            }
            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Submit a new order for the given DNS names.
     *
     * @param string[] $dns DNS names to request order for
     *
     * @return Promise resolves to an Order object
     * @throws AcmeException If something went wrong.
     * @api
     *
     */
    public function newOrder(array $dns): Promise
    {
        return call(function () use ($dns) {
            /** @var Response $response */

            $identifiers = [];
            foreach ($dns as $dnsName) {
                $identifiers[] = ['type' => 'dns', 'value' => $dnsName];
            }
            $response = yield $this->acmeClient->post(AcmeResource::NEW_ORDER, [
                'identifiers' => $identifiers,
            ]);

            if (\in_array($response->getStatus(), [200, 201])) {
                if (!$response->hasHeader('location')) {
                    throw new AcmeException('Protocol Violation: No Location Header');
                }

                $payload = \json_decode(yield $response->getBody()->buffer());
                $payload->location = $response->getHeader('location');
                return Order::fromResponse($payload);
            }
            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Answers a challenge and signals that the CA should validate it.
     *
     * @param string $location URI of the challenge
     * @param string $keyAuth key authorization
     *
     * @return Promise resolves to the decoded JSON response
     * @throws AcmeException If something went wrong.
     * @api
     *
     */
    public function answerChallenge(string $location, string $keyAuth): Promise
    {
        return call(function () use ($location, $keyAuth) {
            /** @var Response $response */
            $response = yield $this->acmeClient->post($location, [
                'keyAuthorization' => $keyAuth,
            ]);

            try {
                $payload = \json_decode(yield $response->getBody()->buffer());
                return Challenge::fromResponse($payload);
            } catch (\Throwable $_) {
                throw $this->generateException($response, yield $response->getBody()->buffer());
            }
        });
    }

    /**
     * Gets the authorization given a challenge-URL.
     *
     * @param string $location
     *
     * @return Promise
     */
    public function getAuthorization(string $location): Promise
    {
        return call(function () use ($location) {
            /** @var Response $response */
            $response = yield $this->acmeClient->post($location, []);

            try {
                $data = \json_decode(yield $response->getBody()->buffer());
                return Authorization::fromResponse($data);
            } catch (\Throwable $_) {
                throw $this->generateException($response, yield $response->getBody()->buffer());
            }
        });
    }

    /**
     * Polls until a challenge has been validated.
     *
     * @param string $location URI of the challenge
     *
     * @return Promise resolves to null
     * @throws AcmeException
     * @api
     *
     */
    public function pollForChallenge(string $location): Promise
    {
        return call(function () use ($location) {
            do {
                /** @var Response $response */
                $response = yield $this->acmeClient->post($location, []);
                $body = yield $response->getBody()->buffer();
                $data = \json_decode($body);

                if ($data->status === 'pending') {
                    if (!$response->hasHeader('retry-after')) {
                        // throw new AcmeException("Protocol Violation: No Retry-After Header!");

                        yield new Delayed(1000);
                        continue;
                    }

                    $waitTime = $this->parseRetryAfter($response->getHeader('retry-after'));
                    $waitTime = \max($waitTime, 1);

                    yield new Delayed($waitTime * 1000);
                    continue;
                }

                if ($data->status === 'invalid') {
                    $errors = [];

                    foreach ($data->errors ?? [] as $error) {
                        $message = $error->title ?? '???';

                        if ($error->detail ?? '') {
                            $message .= ' (' . $error->detail . ')';
                        }

                        $errors[] = $message;
                    }

                    throw new AcmeException('Challenge marked as invalid: ' . ($errors ? \implode(
                        ', ',
                        $errors
                    ) : ('Unknown error: ' . $body)));
                }

                if ($data->status === 'valid') {
                    break;
                }

                throw new AcmeException("Invalid challenge status: {$data->status}.");
            } while (1);
        });
    }

    /**
     * Requests a new certificate. This will be done with the finalize URL which is created upon order creation.
     *
     * @param string $csr certificate signing request
     *
     * @param string $location
     *
     * @return Promise resolves to the URI where the certificate will be provided
     * @api
     *
     */
    public function finalizeOrder(string $location, string $csr): Promise
    {
        return call(function () use ($location, $csr) {
            $begin = 'REQUEST-----';
            $end = '----END';

            $beginPos = \strpos($csr, $begin) + \strlen($begin);

            if ($beginPos === false) {
                throw new InvalidArgumentException("Invalid CSR, maybe not in PEM format?\n{$csr}");
            }

            $csr = \substr($csr, $beginPos);

            $endPos = \strpos($csr, $end);

            if ($endPos === false) {
                throw new InvalidArgumentException("Invalid CSR, maybe not in PEM format?\n{$csr}");
            }

            $csr = \substr($csr, 0, $endPos);

            /** @var Response $response */
            $response = yield $this->acmeClient->post($location, [
                'csr' => base64UrlEncode(\base64_decode($csr)),
            ]);

            if ($response->getStatus() === 200) {
                if (!$response->hasHeader('location')) {
                    throw new AcmeException('Protocol Violation: No Location Header');
                }

                $payload = \json_decode(yield $response->getBody()->buffer());
                $payload->location = $response->getHeader('location');
                return Order::fromResponse($payload);
            }

            throw $this->generateException($response, yield $response->getBody()->buffer());
        });
    }

    /**
     * Polls for a certificate.
     *
     * @param string $location URI of the certificate
     *
     * @return Promise resolves to the complete certificate chain as array of PEM encoded certificates
     * @throws AcmeException If something went wrong.
     * @api
     *
     */
    public function pollForCertificate(string $location): Promise
    {
        return call(function () use ($location) {
            do {
                /** @var Response $response */
                $response = yield $this->acmeClient->post($location, []);

                if ($response->getStatus() === 202) {
                    if (!$response->hasHeader('retry-after')) {
                        // throw new AcmeException("Protocol Violation: No Retry-After Header!");

                        yield new Delayed(1000);
                        continue;
                    }

                    $waitTime = $this->parseRetryAfter($response->getHeader('retry-after'));
                    $waitTime = \min(\max($waitTime, 2), 60);

                    yield new Delayed($waitTime * 1000);
                    continue;
                }

                if ($response->getStatus() === 200) {
                    $certificates = [
                        yield $response->getBody()->buffer(),
                    ];

                    // prevent potential infinite loop
                    $maximumChainLength = 5;

                    while ($response->hasHeader('link')) {
                        $links = $response->getHeaderArray('link');
                        $hasUplink = false;
                        foreach ($links as $link) {
                            if (\preg_match('#<(.*?)>;rel="up"#x', $link, $match)) {
                                $url = resolve($response->getRequest()->getUri(), $match[1]);

                                /** @var Response $response */
                                $response = yield $this->acmeClient->post($url, []);
                                $certificates[] = yield $response->getBody()->buffer();
                                $hasUplink = true;
                            }
                        }

                        if (!$hasUplink) {
                            break; // No uplinks in this response. Break out :)
                        }

                        if (!$maximumChainLength--) {
                            throw new AcmeException('Too long certificate chain');
                        }
                    }

                    return $certificates;
                }
            } while (true);
        });
    }

    /**
     * Revokes a certificate.
     *
     * @param string $pem PEM encoded certificate
     *
     * @return Promise resolves to true
     * @throws AcmeException If something went wrong.
     * @api
     *
     */
    public function revokeCertificate(string $pem): Promise
    {
        return call(function () use ($pem) {
            $der = Certificate::pemToDer($pem);

            /** @var Response $response */
            $response = yield $this->acmeClient->post(AcmeResource::REVOKE_CERTIFICATE, [
                'certificate' => \strtr(\rtrim(\base64_encode($der), '='), '-/', '+_'),
            ]);

            if ($response->getStatus() === 200) {
                return true;
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
