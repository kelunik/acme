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
use InvalidArgumentException;

/**
 * Verifies HTTP-01 challenges.
 *
 * @package Kelunik\Acme
 */
class Http01Verifier {
    private $client;

    public function __construct(Client $client = null) {
        $this->client = $client ?: new Client(new NullCookieJar);
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
    public function verifyChallenge($domain, $token, $payload) {
        return \Amp\resolve($this->doVerifyChallenge($domain, $token, $payload));
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
    private function doVerifyChallenge($domain, $token, $payload) {
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
        $response = (yield $this->client->request($uri, [
            Client::OP_CRYPTO => [
                "verify_peer" => false,
                "verify_peer_name" => false,
            ],
        ]));

        if (rtrim($payload) !== rtrim($response->getBody())) {
            throw new AcmeException("selfVerify failed, please check {$uri}.");
        }
    }
}