<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\Cookie\NullCookieJar;
use Amp\Artax\Request;
use Amp\Artax\Response;
use Amp\Deferred;
use Amp\Failure;
use Amp\Promise;
use Amp\Success;
use Generator;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\SimpleJWS;
use Throwable;
use function Amp\pipe;
use function Amp\resolve;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class AcmeClient {
    private $http;
    private $keyPair;
    private $dictionaryUri;
    private $dictionary;
    private $nonces;

    public function __construct(string $dictionaryUri, KeyPair $keyPair, Client $http = null) {
        $this->dictionaryUri = $dictionaryUri;
        $this->keyPair = $keyPair;
        $this->http = $http ?: new Client(new NullCookieJar);
        $this->nonces = [];
    }

    private function getNonce(string $uri): Promise {
        if (empty($this->nonces)) {
            return $this->requestNonce($uri);
        }

        return new Success(array_shift($this->nonces));
    }

    private function requestNonce(string $uri): Promise {
        $deferred = new Deferred;

        $request = (new Request)->setMethod("HEAD")->setUri($uri);
        $this->http->request($request)->when(function (Throwable $error = null, Response $response = null) use ($deferred) {
            if ($error) {
                $deferred->fail(new AcmeException("Couldn't fetch nonce!", $error));
            } else {
                if (!$response->hasHeader("replay-nonce")) {
                    $deferred->fail(new AcmeException("Server didn't send required replay-nonce header!"));
                }

                list($nonce) = $response->getHeader("replay-nonce");
                $deferred->succeed($nonce);
            }
        });

        return $deferred->promise();
    }

    private function getResourceUri(string $resource): Promise {
        if (substr($resource, 0, 8) === "https://") {
            return new Success($resource);
        }

        if (!$this->dictionary) {
            return pipe(resolve($this->fetchDictionary()), function () use ($resource) {
                return $this->getResourceUri($resource);
            });
        }

        if (isset($this->dictionary[$resource])) {
            return new Success($this->dictionary[$resource]);
        }

        return new Failure(new AcmeException("Unknown resource: " . $resource));
    }

    private function fetchDictionary(): Generator {
        $response = yield $this->http->request($this->dictionaryUri);

        if ($response->getStatus() !== 200) {
            throw new AcmeException("Invalid directory response code: " . $response->getStatus());
        }

        $this->dictionary = json_decode($response->getBody(), true) ?? [];
        $this->saveNonce($response);
    }

    public function get(string $resource): Promise {
        return resolve($this->doGet($resource));
    }

    private function doGet(string $resource): Generator {
        $uri = yield $this->getResourceUri($resource);

        $response = yield $this->http->request($uri);
        $this->saveNonce($response);

        return $response;
    }

    public function post(string $resource, array $payload): Promise {
        return resolve($this->doPost($resource, $payload));
    }

    private function doPost(string $resource, array $payload): Generator {
        $privateKey = openssl_pkey_get_private($this->keyPair->getPrivate());
        $details = openssl_pkey_get_details($privateKey);

        if ($details["type"] !== OPENSSL_KEYTYPE_RSA) {
            throw new \RuntimeException("Only RSA keys are supported right now.");
        }

        $uri = yield $this->getResourceUri($resource);

        $enc = new Base64UrlSafeEncoder();
        $jws = new SimpleJWS([
            "alg" => "RS256",
            "jwk" => [
                "kty" => "RSA",
                "n" => $enc->encode($details["rsa"]["n"]),
                "e" => $enc->encode($details["rsa"]["e"]),
            ],
            "nonce" => yield $this->getNonce($uri),
        ]);

        $payload["resource"] = $payload["resource"] ?? $resource;

        $jws->setPayload($payload);
        $jws->sign($privateKey);

        $request = (new Request)->setMethod("POST")->setUri($uri)->setBody($jws->getTokenString());

        $response = yield $this->http->request($request);
        $this->saveNonce($response);

        return $response;
    }

    private function saveNonce(Response $response) {
        if (!$response->hasHeader("replay-nonce")) {
            return;
        }

        list($nonce) = $response->getHeader("replay-nonce");
        $this->nonces[] = $nonce;
    }
}