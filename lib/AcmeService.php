<?php

namespace Kelunik\Acme;

use Amp\Artax\Response;
use Amp\Pause;
use Amp\Promise;
use Generator;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\SimpleJWS;
use stdClass;
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

        if (!$cert = @openssl_x509_read($rawCert)) {
            return [true, -1];
        }

        if (!preg_match("#-----BEGIN ([A-Z]+ )?PRIVATE KEY-----#", $rawCert)) {
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

        $challenge = $challenges[$goodChallenges[0]];
        $token = $challenge->token;

        if (!preg_match("#^[a-zA-Z-_]+$#", $token)) {
            throw new AcmeException("Protocol Violation: Invalid Token!");
        }

        $payload = $this->signChallenge($token);

        yield $this->acmeAdapter->provideChallenge($dns, $token, $payload);

        yield $this->answerChallenges($location, $challenge);
        yield $this->pollForStatus($location);

        $location = yield $this->requestCertificate($dns);
        yield $this->pollForCertificate($location, $dns);
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

        throw new AcmeException("Invalid Response Code: " . $response->getStatus());
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

        if ($response->getStatus() === 200) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol Violation: No Location Header!");
            }

            return [$response->getHeader("location"), json_decode($response->getBody())];
        }

        throw new AcmeException("Invalid Response Code: " . $response->getStatus());
    }

    private function answerChallenges(string $location, stdClass $challenge): Promise {
        return resolve($this->doAnswerChallenges($location, $challenge));
    }

    private function doAnswerChallenges(string $location, stdClass $challenge): Generator {
        /** @var Response $response */
        $response = yield $this->acmeClient->post($location, [
            "resource" => AcmeResource::AUTHORIZATION,
            "type" => $challenge->type,
            "token" => $challenge->token,
        ]);

        if ($response->getStatus() === 200) {
            return json_decode($response->getBody());
        }

        throw new AcmeException("Invalid Response Code: " . $response->getStatus());
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
                if ($response->hasHeader("retry-after")) {
                    throw new AcmeException("Protocol Violation: No Retry-After Header!");
                }

                $waitTime = $this->parseRetryAfter($response->getHeader("retry-after")[0]);
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
        $response = yield $this->client->post(AcmeResource::NEW_CERTIFICATE, [
            "csr" => $enc->encode(base64_decode($csr)),
        ]);

        if ($response->getStatus() === 201) {
            if (!$response->hasHeader("location")) {
                throw new AcmeException("Protocol Violation: No Location Header");
            }

            return $response->getHeader("location");
        }

        throw new AcmeException("Invalid Response Code: " . $response->getStatus());
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
                $pem = chunk_split(base64_encode($response->getBody()), 64, "\n");
                $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";

                yield put(yield $this->acmeAdapter->getCertificatePath($dns), $pem);
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
        $jws = new SimpleJWS([
            "alg" => "RS256",
            "jwk" => [
                "kty" => "RSA",
                "n" => $enc->encode($details["rsa"]["n"]),
                "e" => $enc->encode($details["rsa"]["e"]),
            ],
        ]);

        $jws->setPayload([
            "keyAuthorization" => $token,
        ]);

        $jws->sign($privateKey);

        return $jws->getTokenString();
    }
}