<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\Cookie\NullCookieJar;
use Amp\Artax\Response;
use Amp\CoroutineResult;
use Amp\Dns\NoRecordException;
use Amp\Dns\Record;
use Amp\Dns\ResolutionException;
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
     * @param KeyPair $keyPair domain key pair
     * @param array   $domains domains to include in the certificate (first will be used as common name)
     * @return \Amp\Promise resolves to the URI where the certificate will be provided
     * @throws AcmeException If something went wrong.
     */
    public function requestCertificate(KeyPair $keyPair, array $domains) {
        return \Amp\resolve($this->doRequestCertificate($keyPair, $domains));
    }

    /**
     * Requests a new certificate.
     *
     * @param KeyPair $keyPair domain key pair
     * @param array   $domains domains to include in the certificate (first will be used as common name)
     * @return \Generator coroutine resolved by Amp returning the URI where the certificate will be provided
     * @throws AcmeException If something went wrong.
     */
    private function doRequestCertificate(KeyPair $keyPair, array $domains) {
        if (empty($domains)) {
            throw new AcmeException("Parameter \$domains must not be empty.");
        }

        if (!$privateKey = openssl_pkey_get_private($keyPair->getPrivate())) {
            // TODO: Improve error message
            throw new AcmeException("Couldn't use private key.");
        }

        $tempFile = tempnam(sys_get_temp_dir(), "acme_openssl_config_");
        $tempConf = <<<EOL
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @san

[ san ]
EOL;

        $i = 0;

        $san = implode("\n", array_map(function ($dns) use (&$i) {
            $i++;

            return "DNS.{$i} = {$dns}";
        }, $domains));

        yield \Amp\File\put($tempFile, $tempConf . "\n" . $san . "\n");

        $csr = openssl_csr_new([
            "CN" => reset($domains),
            "ST" => "Germany",
            "C" => "DE",
            "O" => "Unknown",
        ], $privateKey, [
            "digest_alg" => "sha256",
            "req_extensions" => "v3_req",
            "config" => $tempFile,
        ]);

        yield \Amp\File\unlink($tempFile);

        if (!$csr) {
            // TODO: Improve error message
            throw new AcmeException("CSR could not be generated.");
        }

        openssl_csr_export($csr, $csr);

        $begin = "REQUEST-----";
        $end = "----END";

        $csr = substr($csr, strpos($csr, $begin) + strlen($begin));
        $csr = substr($csr, 0, strpos($csr, $end));

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
     * Generates the payload which must be provided in HTTP-01 challenges.
     *
     * @api
     * @param KeyPair $accountKeyPair account key pair
     * @param string  $token challenge token
     * @return string payload to be provided at /.well-known/acme-challenge/$token
     * @throws AcmeException If something went wrong.
     */
    public function generateHttp01Payload(KeyPair $accountKeyPair, $token) {
        if (!is_string($token)) {
            throw new InvalidArgumentException(sprintf("\$token must be of type string, %s given.", gettype($token)));
        }

        if (!$privateKey = openssl_pkey_get_private($accountKeyPair->getPrivate())) {
            throw new AcmeException("Couldn't read private key.");
        }

        if (!$details = openssl_pkey_get_details($privateKey)) {
            throw new AcmeException("Couldn't get private key details.");
        }

        if ($details["type"] !== OPENSSL_KEYTYPE_RSA) {
            throw new AcmeException("Key type not supported, only RSA supported currently.");
        }

        $enc = new Base64UrlSafeEncoder;

        $payload = [
            "e" => $enc->encode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n" => $enc->encode($details["rsa"]["n"]),
        ];

        return $token . "." . $enc->encode(hash("sha256", json_encode($payload), true));
    }

    /**
     * Verifies a HTTP-01 challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @api
     * @param string $domain domain to verify
     * @param string $token challenge token
     * @param string $payload expected payload
     * @return \Amp\Promise resolves to null
     * @throws AcmeException If the challenge could not be verified.
     */
    public function verifyHttp01Challenge($domain, $token, $payload) {
        return \Amp\resolve($this->doVerifyHttp01Challenge($domain, $token, $payload));
    }

    /**
     * Verifies a HTTP-01 challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @param string $domain domain to verify
     * @param string $token challenge token
     * @param string $payload expected payload
     * @return \Generator coroutine resolved by Amp returning null
     * @throws AcmeException If the challenge could not be verified.
     */
    private function doVerifyHttp01Challenge($domain, $token, $payload) {
        if (!is_string($domain)) {
            throw new InvalidArgumentException(sprintf("\$domain must be of type string, %s given.", gettype($domain)));
        }

        if (!is_string($token)) {
            throw new InvalidArgumentException(sprintf("\$token must be of type string, %s given.", gettype($token)));
        }

        if (!is_string($payload)) {
            throw new InvalidArgumentException(sprintf("\$payload must be of type string, %s given.", gettype($payload)));
        }

        $uri = "http://{$domain}/.well-known/acme-challenge/{$token}";

        $client = new Client(new NullCookieJar);

        /** @var Response $response */
        $response = (yield $client->request($uri, [
            Client::OP_CRYPTO => [
                "verify_peer" => false,
                "verify_peer_name" => false,
            ],
        ]));

        if (rtrim($payload) !== rtrim($response->getBody())) {
            throw new AcmeException("selfVerify failed, please check {$uri}.");
        }
    }

    /**
     * Verifies a DNS-01 Challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @api
     * @param string $domain domain to verify
     * @param string $dnsPayload expected payload
     * @return \Amp\Promise resolves to the DNS entry found
     * @throws AcmeException If the challenge could not be verified.
     */
    public function verifyDns01Challenge($domain, $dnsPayload) {
        return \Amp\resolve($this->doVerifyDns01Challenge($domain, $dnsPayload));
    }

    /**
     * Verifies a DNS-01 Challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @param string $domain domain to verify
     * @param string $dnsPayload expected payload
     * @return \Generator coroutine resolved to the DNS entry found
     * @throws AcmeException If the challenge could not be verified.
     */
    private function doVerifyDns01Challenge($domain, $dnsPayload) {
        if (!is_string($domain)) {
            throw new InvalidArgumentException(sprintf("\$domain must be of type string, %s given.", gettype($domain)));
        }

        if (!is_string($dnsPayload)) {
            throw new InvalidArgumentException(sprintf("\$dnsPayload must be of type string, %s given.", gettype($dnsPayload)));
        }

        $uri = "_acme-challenge." . $domain;

        try {
            $dnsResponse = (yield \Amp\Dns\query($uri, ["types" => Record::TXT]));
        } catch (NoRecordException $e) {
            throw new AcmeException("Verification failed, no TXT record found for '{$uri}'.", 0, $e);
        } catch (ResolutionException $e) {
            throw new AcmeException("Verification failed, couldn't query TXT record of '{$uri}': " . $e->getMessage(), 0, $e);
        }

        list($record) = $dnsResponse;
        list($payload) = $record;

        if ($payload !== $dnsPayload) {
            throw new AcmeException("Verification failed, please check DNS record under '{$uri}'.");
        }

        yield new CoroutineResult($dnsResponse);
        return;
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
