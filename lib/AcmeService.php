<?php

namespace Kelunik\Acme;

use Amp\Artax\Response;
use Amp\Pause;
use Amp\Promise;
use Generator;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use function Amp\File\exists;
use function Amp\File\get;
use function Amp\File\put;
use function Amp\resolve;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class AcmeService {
    private $acmeClient;
    private $accountKeyPair;

    public function __construct(AcmeClient $acmeClient, KeyPair $accountKeyPair) {
        $this->acmeClient = $acmeClient;
        $this->accountKeyPair = $accountKeyPair;
    }

    public function register(string $email, string $agreement = null): Promise {
        return resolve($this->doRegister($email, $agreement));
    }

    private function doRegister(string $email, string $agreement = null): Generator {
        $payload = [
            "contact" => [
                "mailto:{$email}",
            ],
        ];

        if ($agreement) {
            $payload["agreement"] = $agreement;
        }

        /** @var Response $response */
        $response = yield $this->acmeClient->post(AcmeResource::NEW_REGISTRATION, $payload);

        if ($response->getStatus() === 201) {
            $payload = json_decode($response->getBody());

            return new Registration($payload->contact, $payload->agreement, $payload->authorizations, $payload->certificates);
        }

        if ($response->getStatus() === 409) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol violation: 409 Conflict response didn't carry any location header!");
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

            $response = yield $this->acmeClient->post($location, $payload);
            $payload = json_decode($response->getBody());

            return new Registration($payload->contact, $payload->agreement, $payload->authorizations, $payload->certificates);
        }

        throw new AcmeException("Invalid Response Code: " . $response->getStatus() . " " . $response->getBody());
    }

    public function requestChallenges(string $dns): Promise {
        return resolve($this->doRequestChallenges($dns));
    }

    private function doRequestChallenges(string $dns): Generator {
        /** @var Response $response */
        $response = yield $this->acmeClient->post(AcmeResource::NEW_AUTHORIZATION, [
            "identifier" => [
                "type" => "dns",
                "value" => $dns,
            ],
        ]);

        if ($response->getStatus() === 201) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol Violation: No Location Header!");
            }

            return [current($response->getHeader("location")), json_decode($response->getBody())];
        }

        throw new AcmeException("Invalid Response Code: " . $response->getStatus() . " " . $response->getBody());
    }

    public function answerChallenge(string $location, string $keyAuth): Promise {
        return resolve($this->doAnswerChallenge($location, $keyAuth));
    }

    private function doAnswerChallenge(string $location, string $keyAuth): Generator {
        /** @var Response $response */
        $response = yield $this->acmeClient->post($location, [
            "resource" => AcmeResource::CHALLENGE,
            "keyAuthorization" => $keyAuth,
        ]);

        if ($response->getStatus() === 202) {
            return json_decode($response->getBody());
        }

        throw new AcmeException("Invalid Response Code: " . $response->getStatus() . " " . $response->getBody());
    }

    public function pollForChallenge(string $location): Promise {
        return resolve($this->doPollForChallenge($location));
    }

    private function doPollForChallenge(string $location): Generator {
        do {
            /** @var Response $response */
            $response = yield $this->acmeClient->get($location);
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
                throw new AcmeException("Invalid challenge status: " . $data->status);
            }
        } while (1);
    }

    public function requestCertificate(KeyPair $keyPair, array $domains): Promise {
        return resolve($this->doRequestCertificate($keyPair, $domains));
    }

    private function doRequestCertificate(KeyPair $keyPair, array $domains): Generator {
        if (!$privateKey = openssl_pkey_get_private($keyPair->getPrivate())) {
            throw new AcmeException("Couldn't use private key");
        }

        $san = implode(",", array_map(function ($dns) {
            return "DNS:" . $dns;
        }, $domains));

        $csr = openssl_csr_new([
            "CN" => reset($domains),
            "ST" => "Germany",
            "C" => "DE",
            "O" => "Unknown",
            "subjectAltName" => $san,
            "basicConstraints" => "CA:FALSE",
            "extendedKeyUsage" => "serverAuth",
        ], $privateKey, [
            "digest_alg" => "sha256",
            "req_extensions" => "v3_req",
        ]);

        if (!$csr) {
            throw new AcmeException("CSR couldn't be generated!");
        }

        openssl_csr_export($csr, $csr);

        $begin = "REQUEST-----";
        $end = "----END";

        $csr = substr($csr, strpos($csr, $begin) + strlen($begin));
        $csr = substr($csr, 0, strpos($csr, $end));

        $enc = new Base64UrlSafeEncoder;

        /** @var Response $response */
        $response = yield $this->acmeClient->post(AcmeResource::NEW_CERTIFICATE, [
            "csr" => $enc->encode(base64_decode($csr)),
        ]);

        if ($response->getStatus() === 201) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol Violation: No Location Header");
            }

            return current($response->getHeader("location"));
        }

        throw new AcmeException("Invalid response code: " . $response->getStatus() . "\n" . $response->getBody());
    }

    public function pollForCertificate(string $location): Promise {
        return resolve($this->doPollForCertificate($location));
    }

    private function doPollForCertificate(string $location): Generator {
        do {
            /** @var Response $response */
            $response = yield $this->acmeClient->get($location);

            if ($response->getStatus() === 202) {
                if (!$response->hasHeader("retry-after")) {
                    throw new AcmeException("Protocol Violation: No Retry-After Header");
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
                            $response = yield $this->acmeClient->get($uri);

                            $pem = chunk_split(base64_encode($response->getBody()), 64, "\n");
                            $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
                            $certificates[] = $pem;
                        }
                    }
                }

                return $certificates;
            }
        } while (1);

        throw new AcmeException("Couldn't fetch certificate");
    }

    private function parseRetryAfter(string $header) {
        if (preg_match("#^[0-9]+$#", $header)) {
            return (int) $header;
        }

        $time = @strtotime($header);

        if ($time === false) {
            throw new AcmeException("Invalid retry-after header");
        }

        return max($time - time(), 0);
    }

    public function generateHttp01Payload(string $token): string {
        if (!$privateKey = openssl_pkey_get_private($this->accountKeyPair->getPrivate())) {
            throw new AcmeException("Couldn't read private key");
        }

        if (!$details = openssl_pkey_get_details($privateKey)) {
            throw new AcmeException("Couldn't get private key details");
        }

        if ($details["type"] !== OPENSSL_KEYTYPE_RSA) {
            throw new AcmeException("Key type not supported, only RSA supported currently");
        }

        $enc = new Base64UrlSafeEncoder;

        $payload = [
            "e" => $enc->encode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n" => $enc->encode($details["rsa"]["n"]),
        ];

        return $token . "." . $enc->encode(hash("sha256", json_encode($payload), true));
    }

    public function getAuthorizations(Registration $registration) {
        /** @var Response $response */
        $response = $this->acmeClient->post($registration->getAuthorizations(), [
            "resource" => AcmeResource::REGISTRATION,
        ]);

        if ($response->getStatus() !== 200) {
            throw new AcmeException("Invalid response code: " . $response->getStatus() . "\n" . $response->getBody());
        }

        return json_decode($response->getBody());
    }

    public function getCertificates(Registration $registration) {
        /** @var Response $response */
        $response = $this->acmeClient->post($registration->getAuthorizations(), [
            "resource" => AcmeResource::REGISTRATION,
        ]);

        if ($response->getStatus() !== 200) {
            throw new AcmeException("Invalid response code: " . $response->getStatus() . "\n" . $response->getBody());
        }

        return json_decode($response->getBody());
    }
}