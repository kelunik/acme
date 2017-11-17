<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\Artax\Response;
use Amp\Delayed;
use Amp\Promise;
use InvalidArgumentException;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use function Amp\call;

/**
 * High level ACME client.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class AcmeService {
    /**
     * @var AcmeClient low level ACME client
     */
    private $acmeClient;

    /**
     * AcmeService constructor.
     *
     * @api
     *
     * @param AcmeClient $acmeClient ACME client
     */
    public function __construct(AcmeClient $acmeClient) {
        $this->acmeClient = $acmeClient;
    }

    /**
     * Registers a new account on the server.
     *
     * @api
     *
     * @param string      $email e-mail address for contact
     * @param string|null $agreement agreement URI or null if not agreed yet
     *
     * @return Promise resolves to a Registration object
     * @throws AcmeException If something went wrong.
     */
    public function register($email, $agreement = null): Promise {
        return call(function () use ($email, $agreement) {
            $payload = [
                'contact' => [
                    "mailto:{$email}",
                ],
            ];

            if ($agreement) {
                $payload['agreement'] = $agreement;
            }

            /** @var Response $response */
            $response = yield $this->acmeClient->post(AcmeResource::NEW_REGISTRATION, $payload);

            if ($response->getStatus() === 201) {
                if (!$response->hasHeader('location')) {
                    throw new AcmeException('Protocol Violation: No Location Header');
                }

                $location = $response->getHeader('location');

                $payload = json_decode(yield $response->getBody());

                if ($response->hasHeader('link')) {
                    $links = $response->getHeaderArray('link');

                    foreach ($links as $link) {
                        if (preg_match('#<(.*?)>;rel="terms-of-service"#x', $link, $match)) {
                            $uri = \Sabre\Uri\resolve($response->getRequest()->getUri(), $match[1]);
                            return $this->register($email, $uri);
                        }
                    }
                }

                $contact = $payload->contact ?? [];
                $agreement = $payload->agreement ?? null;
                $authorizations = $payload->authorizations ?? [];
                $certificates = $payload->certificates ?? [];

                return new Registration($location, $contact, $agreement, $authorizations, $certificates);
            }

            if ($response->getStatus() === 409) {
                if (!$response->hasHeader('location')) {
                    throw new AcmeException("Protocol violation: 409 Conflict. Response didn't carry any location header.");
                }

                $location = $response->getHeader('location');

                $payload = [
                    'resource' => AcmeResource::REGISTRATION,
                    'contact' => [
                        "mailto:{$email}",
                    ],
                ];

                if ($agreement) {
                    $payload['agreement'] = $agreement;
                }

                $response = yield $this->acmeClient->post($location, $payload);
                $payload = json_decode(yield $response->getBody());

                if ($response->hasHeader('link')) {
                    $links = $response->getHeaderArray('link');

                    foreach ($links as $link) {
                        if (preg_match('#<(.*?)>;rel="terms-of-service"#x', $link, $match)) {
                            $uri = \Sabre\Uri\resolve($response->getRequest()->getUri(), $match[1]);

                            if ($uri !== $agreement) {
                                return $this->register($email, $uri);
                            }
                        }
                    }
                }

                $contact = $payload->contact ?? [];
                $agreement = $payload->agreement ?? null;

                return new Registration($location, $contact, $agreement);
            }

            throw $this->generateException($response, yield $response->getBody());
        });
    }

    /**
     * Requests challenges for a given DNS name.
     *
     * @api
     *
     * @param string $dns DNS name to request challenge for
     *
     * @return Promise resolves to an array of challenges
     * @throws AcmeException If something went wrong.
     */
    public function requestChallenges(string $dns): Promise {
        return call(function () use ($dns) {
            /** @var Response $response */
            $response = yield $this->acmeClient->post(AcmeResource::NEW_AUTHORIZATION, [
                'identifier' => [
                    'type' => 'dns',
                    'value' => $dns,
                ],
            ]);

            if ($response->getStatus() === 201) {
                if (!$response->hasHeader('location')) {
                    throw new AcmeException("Protocol violation: Response didn't carry any location header.");
                }

                return [$response->getHeader('location'), json_decode(yield $response->getBody())];
            }

            throw $this->generateException($response, yield $response->getBody());
        });
    }

    /**
     * Answers a challenge and signals that the CA should validate it.
     *
     * @api
     *
     * @param string $location URI of the challenge
     * @param string $keyAuth key authorization
     *
     * @return Promise resolves to the decoded JSON response
     * @throws AcmeException If something went wrong.
     */
    public function answerChallenge(string $location, string $keyAuth): Promise {
        return call(function () use ($location, $keyAuth) {
            /** @var Response $response */
            $response = yield $this->acmeClient->post($location, [
                'resource' => AcmeResource::CHALLENGE,
                'keyAuthorization' => $keyAuth,
            ]);

            if ($response->getStatus() === 202) {
                return json_decode(yield $response->getBody());
            }

            throw $this->generateException($response, yield $response->getBody());
        });
    }

    /**
     * Polls until a challenge has been validated.
     *
     * @api
     *
     * @param string $location URI of the challenge
     *
     * @return Promise resolves to null
     * @throws AcmeException
     */
    public function pollForChallenge(string $location): Promise {
        return call(function () use ($location) {
            do {
                /** @var Response $response */
                $response = yield $this->acmeClient->get($location);
                $data = json_decode(yield $response->getBody());

                if ($data->status === 'pending') {
                    if (!$response->hasHeader('retry-after')) {
                        // throw new AcmeException("Protocol Violation: No Retry-After Header!");

                        yield new Delayed(1000);
                        continue;
                    }

                    $waitTime = $this->parseRetryAfter($response->getHeader('retry-after'));
                    $waitTime = max($waitTime, 1);

                    yield new Delayed($waitTime * 1000);

                    continue;
                }

                if ($data->status === 'invalid') {
                    throw new AcmeException('Challenge marked as invalid!');
                }

                if ($data->status === 'valid') {
                    break;
                }

                throw new AcmeException("Invalid challenge status: {$data->status}.");
            } while (1);
        });
    }

    /**
     * Requests a new certificate.
     *
     * @api
     *
     * @param string $csr certificate signing request
     *
     * @return Promise resolves to the URI where the certificate will be provided
     * @throws AcmeException If something went wrong.
     */
    public function requestCertificate(string $csr): Promise {
        return call(function () use ($csr) {
            $begin = 'REQUEST-----';
            $end = '----END';

            $beginPos = strpos($csr, $begin) + strlen($begin);

            if ($beginPos === false) {
                throw new InvalidArgumentException("Invalid CSR, maybe not in PEM format?\n{$csr}");
            }

            $csr = substr($csr, $beginPos);

            $endPos = strpos($csr, $end);

            if ($endPos === false) {
                throw new InvalidArgumentException("Invalid CSR, maybe not in PEM format?\n{$csr}");
            }

            $csr = substr($csr, 0, $endPos);

            $enc = new Base64UrlSafeEncoder;

            /** @var Response $response */
            $response = yield $this->acmeClient->post(AcmeResource::NEW_CERTIFICATE, [
                'csr' => $enc->encode(base64_decode($csr)),
            ]);

            if ($response->getStatus() === 201) {
                if (!$response->hasHeader('location')) {
                    throw new AcmeException('Protocol Violation: No Location Header');
                }

                return $response->getHeader('location');
            }

            throw $this->generateException($response, yield $response->getBody());
        });
    }

    /**
     * Polls for a certificate.
     *
     * @api
     *
     * @param string $location URI of the certificate
     *
     * @return Promise resolves to the complete certificate chain as array of PEM encoded certificates
     * @throws AcmeException If something went wrong.
     */
    public function pollForCertificate(string $location): Promise {
        return call(function () use ($location) {
            do {
                /** @var Response $response */
                $response = yield $this->acmeClient->get($location);

                if ($response->getStatus() === 202) {
                    if (!$response->hasHeader('retry-after')) {
                        // throw new AcmeException("Protocol Violation: No Retry-After Header!");

                        yield new Delayed(1000);
                        continue;
                    }

                    $waitTime = $this->parseRetryAfter($response->getHeader('retry-after'));
                    $waitTime = min(max($waitTime, 2), 60);

                    yield new Delayed($waitTime * 1000);

                    continue;
                }

                if ($response->getStatus() === 200) {
                    $pem = chunk_split(base64_encode(yield $response->getBody()), 64, "\n");
                    $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";

                    $certificates = [
                        $pem,
                    ];

                    // prevent potential infinite loop
                    $maximumChainLength = 5;

                    while ($response->hasHeader('link')) {
                        if (!$maximumChainLength--) {
                            throw new AcmeException('Too long certificate chain');
                        }

                        $links = $response->getHeaderArray('link');

                        foreach ($links as $link) {
                            if (preg_match('#<(.*?)>;rel="up"#x', $link, $match)) {
                                $uri = \Sabre\Uri\resolve($response->getRequest()->getUri(), $match[1]);
                                $response = yield $this->acmeClient->get($uri);

                                $pem = chunk_split(base64_encode(yield $response->getBody()), 64, "\n");
                                $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
                                $certificates[] = $pem;
                            }
                        }
                    }

                    return $certificates;
                }
            } while (1);

            throw new AcmeException("Couldn't fetch certificate");
        });
    }

    /**
     * Revokes a certificate.
     *
     * @api
     *
     * @param string $pem PEM encoded certificate
     *
     * @return Promise resolves to true
     * @throws AcmeException If something went wrong.
     */
    public function revokeCertificate(string $pem): Promise {
        return call(function () use ($pem) {
            $begin = 'CERTIFICATE-----';
            $end = '----END';

            $pem = substr($pem, strpos($pem, $begin) + strlen($begin));
            $pem = substr($pem, 0, strpos($pem, $end));

            $enc = new Base64UrlSafeEncoder;

            /** @var Response $response */
            $response = yield $this->acmeClient->post(AcmeResource::REVOKE_CERTIFICATE, [
                'certificate' => $enc->encode(base64_decode($pem)),
            ]);

            if ($response->getStatus() === 200) {
                return true;
            }

            throw $this->generateException($response, yield $response->getBody());
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
    private function parseRetryAfter(string $header): int {
        if (preg_match('#^\d+$#', $header)) {
            return (int) $header;
        }

        $time = @strtotime($header);

        if ($time === false) {
            throw new AcmeException("Invalid retry-after header: '{$header}'");
        }

        return max($time - time(), 0);
    }

    /**
     * Generates a new exception using the response to provide details.
     *
     * @param Response $response HTTP response to generate the exception from.
     * @param string   $body HTTP response body.
     *
     * @return AcmeException exception generated from the response body
     */
    private function generateException(Response $response, string $body): AcmeException {
        $status = $response->getStatus();
        $info = json_decode($body);
        $uri = $response->getRequest()->getUri();

        if (isset($info->type, $info->detail)) {
            return new AcmeException("Invalid response: {$info->detail}.\nRequest URI: {$uri}.", $info->type);
        }

        return new AcmeException("Invalid response: {$body}.\nRequest URI: {$uri}.", $status);
    }
}
