<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\Cookie\NullCookieJar;
use Amp\Artax\Response;
use Amp\CoroutineResult;
use Amp\Pause;
use InvalidArgumentException;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;

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

    public function register($email, $agreement = null) {
        if (!is_string($email)) {
            throw new InvalidArgumentException(sprintf("\$email must be of type string, %s given.", gettype($email)));
        }

        if ($agreement !== null && !is_string($agreement)) {
            throw new InvalidArgumentException(sprintf("\$agreement must be of type string, %s given.", gettype($agreement)));
        }

        return \Amp\resolve($this->doRegister($email, $agreement));
    }

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

            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol Violation: No Location Header");
            }
            $r = new Registration($response->getHeader("location")["0"], $payload->contact);
            if(property_exists($payload, "agreement"))
                $r->setAgreement($payload->agreement);
            if(property_exists($payload, "authorizations"))
                $r->setAuthorizations($payload->authorizations);
            if(property_exists($payload, "certificates"))
                $r->setCertificates($payload->certificates);

            yield new CoroutineResult($r);
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

            $r = new Registration($location, $payload->contact);
            if(property_exists($payload, "agreement"))
                $r->setAgreement($payload->agreement);

            yield new CoroutineResult($r);
            return;
        }

        throw $this->generateException($response);
    }

    public function requestChallenges($dns) {
        if (!is_string($dns)) {
            throw new InvalidArgumentException(sprintf("\$dns must be of type string, %s given.", gettype($dns)));
        }

        return \Amp\resolve($this->doRequestChallenges($dns));
    }

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

    public function answerChallenge($location, $keyAuth) {
        if (!is_string($location)) {
            throw new InvalidArgumentException(sprintf("\$location must be of type string, %s given.", gettype($location)));
        }

        if (!is_string($keyAuth)) {
            throw new InvalidArgumentException(sprintf("\$keyAuth must be of type string, %s given.", gettype($keyAuth)));
        }

        return \Amp\resolve($this->doAnswerChallenge($location, $keyAuth));
    }

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

    public function pollForChallenge($location) {
        if (!is_string($location)) {
            throw new InvalidArgumentException(sprintf("\$location must be of type string, %s given.", gettype($location)));
        }

        return \Amp\resolve($this->doPollForChallenge($location));
    }

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

    public function requestCertificate(KeyPair $keyPair, array $domains) {
        return \Amp\resolve($this->doRequestCertificate($keyPair, $domains));
    }

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

    public function pollForCertificate($location) {
        if (!is_string($location)) {
            throw new InvalidArgumentException(sprintf("\$location must be of type string, %s given.", gettype($location)));
        }

        return \Amp\resolve($this->doPollForCertificate($location));
    }

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

    public function selfVerify($domain, $token, $payload) {
        if (!is_string($domain)) {
            throw new InvalidArgumentException(sprintf("\$domain must be of type string, %s given.", gettype($domain)));
        }

        if (!is_string($token)) {
            throw new InvalidArgumentException(sprintf("\$token must be of type string, %s given.", gettype($token)));
        }

        if (!is_string($payload)) {
            throw new InvalidArgumentException(sprintf("\$payload must be of type string, %s given.", gettype($payload)));
        }

        return \Amp\resolve($this->doSelfVerify($domain, $token, $payload));
    }

    private function doSelfVerify($domain, $token, $payload) {
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

        /** @var Response $response */
        $response = (yield (new Client(new NullCookieJar))->request($uri));

        if ($payload !== trim($response->getBody())) {
            throw new AcmeException("selfVerify failed, please check {$uri}.");
        }
    }

    public function revokeCertificate($pem) {
        if (!is_string($pem)) {
            throw new InvalidArgumentException(sprintf("\$pem must be of type string, %s given.", gettype($pem)));
        }

        return \Amp\resolve($this->doRevokeCertificate($pem));
    }

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

    public function generateHttp01Payload($token) {
        if (!is_string($token)) {
            throw new InvalidArgumentException(sprintf("\$token must be of type string, %s given.", gettype($token)));
        }

        if (!$privateKey = openssl_pkey_get_private($this->accountKeyPair->getPrivate())) {
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
