<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\Cookie\NullCookieJar;
use Amp\Artax\Request;
use Amp\Artax\Response;
use Amp\Deferred;
use Amp\Failure;
use Amp\Success;
use Exception;
use InvalidArgumentException;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\SimpleJWS;
use Throwable;

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

    public function __construct($dictionaryUri, KeyPair $keyPair, Client $http = null) {
        if (!is_string($dictionaryUri)) {
            throw new InvalidArgumentException(sprintf("\$dictionaryUri must be of type string, %s given.", gettype($dictionaryUri)));
        }

        $this->dictionaryUri = $dictionaryUri;
        $this->keyPair = $keyPair;
        $this->http = $http ?: new Client(new NullCookieJar);
        $this->nonces = [];
    }

    private function getNonce($uri) {
        if (!is_string($uri)) {
            throw new InvalidArgumentException(sprintf("\$uri must be of type string, %s given.", gettype($uri)));
        }

        if (empty($this->nonces)) {
            return $this->requestNonce($uri);
        }

        return new Success(array_shift($this->nonces));
    }

    private function requestNonce($uri) {
        if (!is_string($uri)) {
            throw new InvalidArgumentException(sprintf("\$uri must be of type string, %s given.", gettype($uri)));
        }

        $deferred = new Deferred;
        $request = (new Request)->setMethod("HEAD")->setUri($uri);

        $this->http->request($request)->when(function ($error = null, Response $response = null) use ($deferred, $uri) {
            if ($error) {
                $deferred->fail(new AcmeException("HEAD request to {$uri} failed, could not obtain a replay nonce.", null, $error));
            } else {
                if (!$response->hasHeader("replay-nonce")) {
                    $deferred->fail(new AcmeException("HTTP response didn't carry replay-nonce header."));
                }

                list($nonce) = $response->getHeader("replay-nonce");
                $deferred->succeed($nonce);
            }
        });

        return $deferred->promise();
    }

    private function getResourceUri($resource) {
        if (!is_string($resource)) {
            throw new InvalidArgumentException(sprintf("\$resource must be of type string, %s given.", gettype($resource)));
        }

        if (substr($resource, 0, 8) === "https://") {
            return new Success($resource);
        }

        if (!$this->dictionary) {
            return \Amp\pipe(\Amp\resolve($this->fetchDictionary()), function () use ($resource) {
                return $this->getResourceUri($resource);
            });
        }

        if (isset($this->dictionary[$resource])) {
            return new Success($this->dictionary[$resource]);
        }

        return new Failure(new AcmeException("Resource not found in directory: '{$resource}'."));
    }

    private function fetchDictionary() {
        try {
            /** @var Response $response */
            $response = (yield $this->http->request($this->dictionaryUri));

            if ($response->getStatus() !== 200) {
                $info = json_decode($response->getBody());

                if (isset($info->type, $info->detail)) {
                    throw new AcmeException("Invalid directory response: {$info->detail}", $info->type);
                }

                throw new AcmeException("Invalid directory response. HTTP response code: " . $response->getStatus());
            }

            $this->dictionary = json_decode($response->getBody(), true) ?: [];
            $this->saveNonce($response);
        } catch(Exception $e) {
            throw new AcmeException("Could not obtain directory.", null, $e);
        } catch(Throwable $e) {
            throw new AcmeException("Could not obtain directory.", null, $e);
        }
    }

    public function get($resource) {
        if (!is_string($resource)) {
            throw new InvalidArgumentException(sprintf("\$resource must be of type string, %s given.", gettype($resource)));
        }

        return \Amp\resolve($this->doGet($resource));
    }

    private function doGet($resource) {
        if (!is_string($resource)) {
            throw new InvalidArgumentException(sprintf("\$resource must be of type string, %s given.", gettype($resource)));
        }

        $uri = (yield $this->getResourceUri($resource));

        try {
            $response = (yield $this->http->request($uri));
            $this->saveNonce($response);
        } catch(Exception $e) {
            throw new AcmeException("GET request to {$uri} failed.", null, $e);
        } catch(Throwable $e) {
            throw new AcmeException("GET request to {$uri} failed.", null, $e);
        }

        yield $response;
    }

    public function post($resource, array $payload) {
        if (!is_string($resource)) {
            throw new InvalidArgumentException(sprintf("\$resource must be of type string, %s given.", gettype($resource)));
        }

        return \Amp\resolve($this->doPost($resource, $payload));
    }

    private function doPost($resource, array $payload) {
        if (!is_string($resource)) {
            throw new InvalidArgumentException(sprintf("\$resource must be of type string, %s given.", gettype($resource)));
        }

        $privateKey = openssl_pkey_get_private($this->keyPair->getPrivate());
        $details = openssl_pkey_get_details($privateKey);

        if ($details["type"] !== OPENSSL_KEYTYPE_RSA) {
            throw new \RuntimeException("Only RSA keys are supported right now.");
        }

        $uri = (yield $this->getResourceUri($resource));

        $enc = new Base64UrlSafeEncoder();
        $jws = new SimpleJWS([
            "alg" => "RS256",
            "jwk" => [
                "kty" => "RSA",
                "n" => $enc->encode($details["rsa"]["n"]),
                "e" => $enc->encode($details["rsa"]["e"]),
            ],
            "nonce" => (yield $this->getNonce($uri)),
        ]);

        $payload["resource"] = isset($payload["resource"]) ? $payload["resource"] : $resource;

        $jws->setPayload($payload);
        $jws->sign($privateKey);

        $request = (new Request)->setMethod("POST")->setUri($uri)->setBody($jws->getTokenString());

        try {
            $response = (yield $this->http->request($request));
            $this->saveNonce($response);
        } catch(Exception $e) {
            throw new AcmeException("POST request to {$uri} failed.", null, $e);
        } catch(Throwable $e) {
            throw new AcmeException("POST request to {$uri} failed.", null, $e);
        }

        yield $response;
    }

    private function saveNonce(Response $response) {
        if (!$response->hasHeader("replay-nonce")) {
            return;
        }

        list($nonce) = $response->getHeader("replay-nonce");
        $this->nonces[] = $nonce;
    }
}
