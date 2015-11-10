<?php

namespace Kelunik\Acme;

use Amp\Artax\Response;
use Amp\Pause;
use Amp\Promise;
use Generator;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use stdClass;
use function Amp\File\exists;
use function Amp\File\get;
use function Amp\File\put;
use function Amp\resolve;
use Throwable;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class AcmeService {
    private $acmeClient;
    private $accountKeyPair;
    private $acmeAdapter;

    public function __construct(AcmeClient $acmeClient, KeyPair $accountKeyPair, AcmeAdapter $acmeAdapter) {
        $this->acmeClient = $acmeClient;
        $this->accountKeyPair = $accountKeyPair;
        $this->acmeAdapter = $acmeAdapter;
    }

    public function getCertificateData(string $dns): Promise {
        return resolve($this->doGetCertificateData($dns));
    }

    private function doGetCertificateData(string $dns): Generator {
        $path = yield $this->acmeAdapter->getCertificatePath($dns);

        if (!yield exists($path)) {
            return [true, -1];
        }

        if (!$rawCert = yield get($path)) {
            return [true, -1];
        }

        if (!preg_match("#-----BEGIN ([A-Z]+ )?PRIVATE KEY-----#", $rawCert, $match)) {
            return [true, -1];
        }

        if (!preg_match("#-----BEGIN CERTIFICATE-----[a-zA-Z0-9-_=/.+\n]+-----END CERTIFICATE-----#", $rawCert, $match)) {
            return [true, -1];
        }

        // check first cert for certificate chains
        $rawCert = $match[0];

        if (!$cert = @openssl_x509_read($rawCert)) {
            return [true, -1];
        }

        if (!$cert = openssl_x509_parse($cert)) {
            return [true, -1];
        }

        $selfSigned = $cert["subject"] === $cert["issuer"];

        $names = $this->parseNamesFromTlsCertArray($cert);

        if (!in_array($dns, $names)) {
            return [$selfSigned, -1];
        }

        if (time() > $cert["validTo_time_t"]) {
            return [$selfSigned, 0];
        }

        return [$selfSigned, $cert["validTo_time_t"] - time()];
    }

    private function parseNamesFromTlsCertArray(array $cert): array {
        $names = [];

        if (!empty($cert["subject"]["CN"])) {
            $names[] = $cert["subject"]["CN"];
        }

        if (empty($cert["extensions"]["subjectAltName"])) {
            return $names;
        }

        $parts = array_map("trim", explode(",", $cert["extensions"]["subjectAltName"]));

        foreach ($parts as $part) {
            if (stripos($part, "DNS:") === 0) {
                $names[] = substr($part, 4);
            }
        }

        return array_map("strtolower", $names);
    }

    public function issueCertificate(string $dns, array $contact, string $agreement = null): Promise {
        return resolve($this->doIssueCertificate($dns, $contact, $agreement));
    }

    private function doIssueCertificate(string $dns, array $contact, string $agreement = null): Generator {
        yield $this->register($contact, $agreement);

        list($location, $challenges) = yield $this->requestChallenges($dns);
        $goodChallenges = $this->findSuitableCombination($challenges);

        if (empty($goodChallenges)) {
            throw new AcmeException("Couldn't find any combination of challenges which this server can solve!");
        }

        $challenge = $challenges->challenges[current($goodChallenges)];
        $token = $challenge->token;

        if (!preg_match("#^[a-zA-Z0-9-_]+$#", $token)) {
            throw new AcmeException("Protocol Violation: Invalid Token!");
        }

        $payload = $this->signChallenge($token);

        yield $this->acmeAdapter->provideChallenge($dns, $token, $payload);

        try {
            yield $this->answerChallenge($challenge->uri, $challenge, $payload);
            yield $this->pollForStatus($location);

            $location = yield $this->requestCertificate($dns);
            yield $this->pollForCertificate($location, $dns);

            yield $this->acmeAdapter->cleanUpChallenge($dns, $token);
        } catch(Throwable $e) {
            yield $this->acmeAdapter->cleanUpChallenge($dns, $token);

            throw $e;
        }

        // no finally because generators...
    }

    private function register(array $contact, string $agreement = null): Promise {
        return resolve($this->doRegister($contact, $agreement));
    }

    private function doRegister(array $contact, string $agreement = null): Generator {
        $payload = [
            "contact" => $contact,
        ];

        if ($agreement) {
            $payload["agreement"] = $agreement;
        }

        /** @var Response $response */
        $response = yield $this->acmeClient->post(AcmeResource::NEW_REGISTRATION, $payload);

        if ($response->getStatus() === 201) {
            return json_decode($response->getBody());
        }

        if ($response->getStatus() === 409) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol violation: 409 Conflict response didn't carry any location header!");
            }

            list($location) = $response->getHeader("location");

            $payload = [
                "resource" => AcmeResource::REGISTRATION,
                "contact" => $contact,
            ];

            if ($agreement) {
                $payload["agreement"] = $agreement;
            }

            $response = yield $this->acmeClient->post($location, $payload);

            return json_decode($response->getBody());
        }

        throw new AcmeException("Invalid Response Code: " . $response->getStatus() . " " . $response->getBody());
    }

    private function requestChallenges(string $dns): Promise {
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

    private function answerChallenge(string $location, stdClass $challenge, string $keyAuth): Promise {
        return resolve($this->doAnswerChallenge($location, $challenge, $keyAuth));
    }

    private function doAnswerChallenge(string $location, stdClass $challenge, string $keyAuth): Generator {
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

    private function pollForStatus(string $location): Promise {
        return resolve($this->doPollForStatus($location));
    }

    private function doPollForStatus(string $location): Generator {
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
                throw new AcmeException("Invalid Challenge Status: " . $data->status);
            }
        } while (1);
    }

    private function requestCertificate(string $dns): Promise {
        return resolve($this->doRequestCertificate($dns));
    }

    private function doRequestCertificate(string $dns): Generator {
        /** @var KeyPair $keyPair */
        $keyPair = yield $this->acmeAdapter->getKeyPair($dns);
        $privateKey = openssl_pkey_get_private($keyPair->getPrivate());

        $csr = openssl_csr_new([
            "commonName" => $dns,
        ], $privateKey, ["digest_alg" => "sha256"]);

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

        throw new AcmeException("Invalid Response Code: " . $response->getStatus() . " " . $response->getBody());
    }

    private function pollForCertificate(string $location, string $dns): Promise {
        return resolve($this->doPollForCertificate($location, $dns));
    }

    private function doPollForCertificate(string $location, string $dns): Generator {
        do {
            /** @var Response $response */
            $response = yield $this->acmeClient->get($location);

            if ($response->getStatus() === 202) {
                if (!$response->hasHeader("retry-after")) {
                    throw new AcmeException("Protocol Violation: No Retry-After Header");
                }

                $waitTime = $this->parseRetryAfter($response->getHeader("retry-after")[0]);
                $waitTime = max($waitTime, 1);

                yield new Pause($waitTime * 1000);

                continue;
            } elseif ($response->getStatus() === 200) {
                $key = yield $this->acmeAdapter->getKeyPair($dns);
                $key = $key->getPrivate();

                $pem = chunk_split(base64_encode($response->getBody()), 64, "\n");
                $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";

                while ($response->hasHeader("link")) {
                    $links = $response->getHeader("link");

                    foreach ($links as $link) {
                        if (preg_match("#<(.*?)>;rel=\"up\"#x", $link, $match)) {
                            $uri = \Sabre\Uri\resolve($response->getRequest()->getUri(), $match[1]);
                            $response = yield $this->acmeClient->get($uri);

                            $pemEnc = chunk_split(base64_encode($response->getBody()), 64, "\n");
                            $pem .= "-----BEGIN CERTIFICATE-----\n" . $pemEnc . "-----END CERTIFICATE-----\n";
                        }
                    }
                }

                yield put(yield $this->acmeAdapter->getCertificatePath($dns), $key . "\n" . $pem . "\n");
            }
        } while (1);
    }

    private function parseRetryAfter(string $header) {
        if (preg_match("#^[0-9]+$#", $header)) {
            return (int) $header;
        }

        $time = @strtotime($header);

        if ($time === false) {
            throw new AcmeException("Invalid Retry-After Header");
        }

        return max($time - time(), 0);
    }

    private function findSuitableCombination(stdClass $response): array {
        $challenges = $response->challenges ?? [];
        $combinations = $response->combinations ?? [];
        $goodChallenges = [];

        foreach ($challenges as $i => $challenge) {
            if ($challenge->type === "http-01") {
                $goodChallenges[] = $i;
            }
        }

        foreach ($goodChallenges as $i => $challenge) {
            if (!in_array([$challenge], $combinations)) {
                unset($goodChallenges[$i]);
            }
        }

        return $goodChallenges;
    }

    private function signChallenge(string $token): string {
        $privateKey = openssl_pkey_get_private($this->accountKeyPair->getPrivate());
        $details = openssl_pkey_get_details($privateKey);

        if ($details["type"] !== OPENSSL_KEYTYPE_RSA) {
            throw new AcmeException("Only RSA keys are supported right now!");
        }

        $enc = new Base64UrlSafeEncoder;
        $details = openssl_pkey_get_details($privateKey);

        $payload = [
            "e" => $enc->encode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n" => $enc->encode($details["rsa"]["n"]),
        ];

        return $token . "." . $enc->encode(hash("sha256", json_encode($payload), true));
    }
}