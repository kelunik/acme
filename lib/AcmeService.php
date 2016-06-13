<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\Artax\Response;
use Amp\CoroutineResult;
use Amp\Pause;
use InvalidArgumentException;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;

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
     * @param AcmeClient $acmeClient ACME client
     */
    public function __construct(AcmeClient $acmeClient) {
        $this->acmeClient = $acmeClient;
    }

    /**
     * Registers a new account on the server.
     *
     * @api
     * @param string      $email e-mail address for contact
     * @param string|null $agreement agreement URI or null if not agreed yet
     * @return \Amp\Promise resolves to a Registration object
     * @throws AcmeException If something went wrong.
     */
    public function register($email, $agreement = null) {
        return \Amp\resolve($this->doRegister($email, $agreement));
    }

    /**
     * Registers a new account on the server.
     *
     * @param string      $email e-mail address for contact
     * @param string|null $agreement agreement URI or null if not agreed yet
     * @return \Generator coroutine resolved by Amp returning a Registration object
     * @throws AcmeException If something went wrong.
     */
    private function doRegister($email, $agreement = null) {
        if (!is_string($email)) {
            throw new InvalidArgumentException(sprintf("\$email must be of type string, %s given.", gettype($email)));
        }

        if ($agreement !== null && !is_string($agreement)) {
            throw new InvalidArgumentException(sprintf("\$agreement must be of type string, %s given.", gettype($agreement)));
        }

        $payload = [
            "contact" => [
                "mailto:{$email}",
            ],
        ];

        if ($agreement) {
            $payload["agreement"] = $agreement;
        }

        /** @var Response $response */
        $response = (yield $this->acmeClient->post(AcmeResource::NEW_REGISTRATION, $payload));

        if ($response->getStatus() === 201) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol Violation: No Location Header");
            }

            list($location) = $response->getHeader("location");

            $payload = json_decode($response->getBody());

            if ($response->hasHeader("link")) {
                $links = $response->getHeader("link");

                foreach ($links as $link) {
                    if (preg_match("#<(.*?)>;rel=\"terms-of-service\"#x", $link, $match)) {
                        $uri = \Sabre\Uri\resolve($response->getRequest()->getUri(), $match[1]);
                        yield new CoroutineResult($this->register($email, $uri));
                        return;
                    }
                }
            }

            $contact = isset($payload->contact) ? $payload->contact : [];
            $agreement = isset($payload->agreement) ? $payload->agreement : null;
            $authorizations = isset($payload->authorizations) ? $payload->authorizations : [];
            $certificates = isset($payload->certificates) ? $payload->certificates : [];

            yield new CoroutineResult(new Registration($location, $contact, $agreement, $authorizations, $certificates));
        }

        if ($response->getStatus() === 409) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol violation: 409 Conflict. Response didn't carry any location header.");
            }

            list($location) = $response->getHeader("location");

            $payload = [
                "resource" => AcmeResource::REGISTRATION,
                "contact" => [
                    "mailto:{$email}",
                ],
            ];

            if ($agreement) {
                $payload["agreement"] = $agreement;
            }

            $response = (yield $this->acmeClient->post($location, $payload));
            $payload = json_decode($response->getBody());

            if ($response->hasHeader("link")) {
                $links = $response->getHeader("link");

                foreach ($links as $link) {
                    if (preg_match("#<(.*?)>;rel=\"terms-of-service\"#x", $link, $match)) {
                        $uri = \Sabre\Uri\resolve($response->getRequest()->getUri(), $match[1]);

                        if ($uri !== $agreement) {
                            yield new CoroutineResult($this->register($email, $uri));
                            return;
                        }
                    }
                }
            }

            $contact = isset($payload->contact) ? $payload->contact : [];
            $agreement = isset($payload->agreement) ? $payload->agreement : null;

            yield new CoroutineResult(new Registration($location, $contact, $agreement));
            return;
        }

        throw $this->generateException($response);
    }

    /**
     * Requests challenges for a given DNS name.
     *
     * @api
     * @param string $dns DNS name to request challenge for
     * @return \Amp\Promise resolves to an array of challenges
     * @throws AcmeException If something went wrong.
     */
    public function requestChallenges($dns) {
        return \Amp\resolve($this->doRequestChallenges($dns));
    }

    /**
     * Requests challenges for a given DNS name.
     *
     * @param string $dns DNS name to request challenge for
     * @return \Generator coroutine resolved by Amp returning an array of challenges
     * @throws AcmeException If something went wrong.
     */
    private function doRequestChallenges($dns) {
        if (!is_string($dns)) {
            throw new InvalidArgumentException(sprintf("\$dns must be of type string, %s given.", gettype($dns)));
        }

        /** @var Response $response */
        $response = (yield $this->acmeClient->post(AcmeResource::NEW_AUTHORIZATION, [
            "identifier" => [
                "type" => "dns",
                "value" => $dns,
            ],
        ]));

        if ($response->getStatus() === 201) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol violation: Response didn't carry any location header.");
            }

            yield new CoroutineResult([current($response->getHeader("location")), json_decode($response->getBody())]);
            return;
        }

        throw $this->generateException($response);
    }

    /**
     * Answers a challenge and signals that the CA should validate it.
     *
     * @api
     * @param string $location URI of the challenge
     * @param string $keyAuth key authorization
     * @return \Amp\Promise resolves to the decoded JSON response
     * @throws AcmeException If something went wrong.
     */
    public function answerChallenge($location, $keyAuth) {
        return \Amp\resolve($this->doAnswerChallenge($location, $keyAuth));
    }

    /**
     * Answers a challenge and signals that the CA should validate it.
     *
     * @param string $location URI of the challenge
     * @param string $keyAuth key authorization
     * @return \Generator coroutine resolved by Amp returning the decoded JSON response
     * @throws AcmeException If something went wrong.
     */
    private function doAnswerChallenge($location, $keyAuth) {
        if (!is_string($location)) {
            throw new InvalidArgumentException(sprintf("\$location must be of type string, %s given.", gettype($location)));
        }

        if (!is_string($keyAuth)) {
            throw new InvalidArgumentException(sprintf("\$keyAuth must be of type string, %s given.", gettype($keyAuth)));
        }

        /** @var Response $response */
        $response = (yield $this->acmeClient->post($location, [
            "resource" => AcmeResource::CHALLENGE,
            "keyAuthorization" => $keyAuth,
        ]));

        if ($response->getStatus() === 202) {
            yield new CoroutineResult(json_decode($response->getBody()));
            return;
        }

        throw $this->generateException($response);
    }

    /**
     * Polls until a challenge has been validated.
     *
     * @api
     * @param string $location URI of the challenge
     * @return \Amp\Promise resolves to null
     * @throws AcmeException
     */
    public function pollForChallenge($location) {
        return \Amp\resolve($this->doPollForChallenge($location));
    }

    /**
     * Polls until a challenge has been validated.
     *
     * @param string $location URI of the challenge
     * @return \Generator coroutine resolved by Amp returning null
     * @throws AcmeException
     */
    private function doPollForChallenge($location) {
        if (!is_string($location)) {
            throw new InvalidArgumentException(sprintf("\$location must be of type string, %s given.", gettype($location)));
        }

        do {
            /** @var Response $response */
            $response = (yield $this->acmeClient->get($location));
            $data = json_decode($response->getBody());

            if ($data->status === "pending") {
                if (!$response->hasHeader("retry-after")) {
                    // throw new AcmeException("Protocol Violation: No Retry-After Header!");

                    yield new Pause(1000);
                    continue;
                }

                $waitTime = $this->parseRetryAfter(current($response->getHeader("retry-after")));
                $waitTime = max($waitTime, 1);

                yield new Pause($waitTime * 1000);

                continue;
            } elseif ($data->status === "invalid") {
                throw new AcmeException("Challenge marked as invalid!");
            } elseif ($data->status === "valid") {
                break;
            } else {
                throw new AcmeException("Invalid challenge status: {$data->status}.");
            }
        } while (1);
    }

    /**
     * Requests a new certificate.
     *
     * @api
     * @param string $csr certificate signing request
     * @return \Amp\Promise resolves to the URI where the certificate will be provided
     * @throws AcmeException If something went wrong.
     */
    public function requestCertificate($csr) {
        return \Amp\resolve($this->doRequestCertificate($csr));
    }

    /**
     * Requests a new certificate.
     *
     * @param string $csr certificate signing request
     * @return \Generator coroutine resolved by Amp returning the URI where the certificate will be provided
     * @throws AcmeException If something went wrong.
     */
    private function doRequestCertificate($csr) {
        if (!is_string($csr)) {
            throw new \InvalidArgumentException(sprintf("\$csr must be of type bool, %s given", gettype($csr)));
        }

        $begin = "REQUEST-----";
        $end = "----END";

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
        $response = (yield $this->acmeClient->post(AcmeResource::NEW_CERTIFICATE, [
            "csr" => $enc->encode(base64_decode($csr)),
        ]));

        if ($response->getStatus() === 201) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol Violation: No Location Header");
            }

            yield new CoroutineResult(current($response->getHeader("location")));
            return;
        }

        throw $this->generateException($response);
    }

    /**
     * Polls for a certificate.
     *
     * @api
     * @param string $location URI of the certificate
     * @return \Amp\Promise resolves to the complete certificate chain as array of PEM encoded certificates
     * @throws AcmeException If something went wrong.
     */
    public function pollForCertificate($location) {
        return \Amp\resolve($this->doPollForCertificate($location));
    }

    /**
     * Polls for a certificate.
     *
     * @param string $location URI of the certificate
     * @return \Generator coroutine resolved by Amp returning the complete certificate chain as array of PEM encoded certificates
     * @throws AcmeException If something went wrong.
     */
    private function doPollForCertificate($location) {
        if (!is_string($location)) {
            throw new InvalidArgumentException(sprintf("\$location must be of type string, %s given.", gettype($location)));
        }

        do {
            /** @var Response $response */
            $response = (yield $this->acmeClient->get($location));

            if ($response->getStatus() === 202) {
                if (!$response->hasHeader("retry-after")) {
                    throw new AcmeException("Protocol violation: Response didn't care any retry-after header.");
                }

                $waitTime = $this->parseRetryAfter($response->getHeader("retry-after")[0]);
                $waitTime = min(max($waitTime, 2), 60);

                yield new Pause($waitTime * 1000);

                continue;
            } elseif ($response->getStatus() === 200) {
                $pem = chunk_split(base64_encode($response->getBody()), 64, "\n");
                $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";

                $certificates = [
                    $pem,
                ];

                // prevent potential infinite loop
                $maximumChainLength = 5;

                while ($response->hasHeader("link")) {
                    if (!$maximumChainLength--) {
                        throw new AcmeException("Too long certificate chain");
                    }

                    $links = $response->getHeader("link");

                    foreach ($links as $link) {
                        if (preg_match("#<(.*?)>;rel=\"up\"#x", $link, $match)) {
                            $uri = \Sabre\Uri\resolve($response->getRequest()->getUri(), $match[1]);
                            $response = (yield $this->acmeClient->get($uri));

                            $pem = chunk_split(base64_encode($response->getBody()), 64, "\n");
                            $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
                            $certificates[] = $pem;
                        }
                    }
                }

                yield new CoroutineResult($certificates);
                return;
            }
        } while (1);

        throw new AcmeException("Couldn't fetch certificate");
    }

    /**
     * Revokes a certificate.
     *
     * @api
     * @param string $pem PEM encoded certificate
     * @return \Amp\Promise resolves to true
     * @throws AcmeException If something went wrong.
     */
    public function revokeCertificate($pem) {
        return \Amp\resolve($this->doRevokeCertificate($pem));
    }

    /**
     * Revokes a certificate.
     *
     * @param string $pem PEM encoded certificate
     * @return \Generator coroutine resolved by Amp returning true
     * @throws AcmeException If something went wrong.
     */
    private function doRevokeCertificate($pem) {
        if (!is_string($pem)) {
            throw new InvalidArgumentException(sprintf("\$pem must be of type string, %s given.", gettype($pem)));
        }

        $begin = "CERTIFICATE-----";
        $end = "----END";

        $pem = substr($pem, strpos($pem, $begin) + strlen($begin));
        $pem = substr($pem, 0, strpos($pem, $end));

        $enc = new Base64UrlSafeEncoder;

        /** @var Response $response */
        $response = (yield $this->acmeClient->post(AcmeResource::REVOKE_CERTIFICATE, [
            "certificate" => $enc->encode(base64_decode($pem)),
        ]));

        if ($response->getStatus() === 200) {
            yield new CoroutineResult(true);
            return;
        }

        throw $this->generateException($response);
    }

    /**
     * Parses a retry header into seconds to wait until a request should be retried.
     *
     * @param string $header header value
     * @return int seconds to wait until retry
     * @throws AcmeException If the header value cannot be parsed.
     */
    private function parseRetryAfter($header) {
        if (!is_string($header)) {
            throw new InvalidArgumentException(sprintf("\$header must be of type string, %s given.", gettype($header)));
        }

        if (preg_match("#^[0-9]+$#", $header)) {
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
     * @param Response $response HTTP response to generate the exception from
     * @return AcmeException exception generated from the response body
     */
    private function generateException(Response $response) {
        $body = $response->getBody();
        $status = $response->getStatus();
        $info = json_decode($body);
        $uri = $response->getRequest()->getUri();

        if (isset($info->type, $info->detail)) {
            return new AcmeException("Invalid response: {$info->detail}.\nRequest URI: {$uri}.", $info->type);
        }

        return new AcmeException("Invalid response: {$body}.\nRequest URI: {$uri}.", $status);
    }
}
