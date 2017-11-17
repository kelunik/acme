<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Verifiers;

use Amp\Artax\Client;
use Amp\Artax\DefaultClient;
use Amp\Artax\Response;
use Amp\Promise;
use Amp\Socket\ClientTlsContext;
use Kelunik\Acme\AcmeException;
use function Amp\call;

/**
 * Verifies HTTP-01 challenges.
 *
 * @package Kelunik\Acme
 */
final class Http01 {
    private $client;

    /**
     * Http01 constructor.
     *
     * @param Client|null $client HTTP client to use, otherwise a default client will be used.
     */
    public function __construct(Client $client = null) {
        $this->client = $client ?? new DefaultClient(null, null, (new ClientTlsContext)->withoutPeerVerification());
    }

    /**
     * Verifies a HTTP-01 challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @api
     *
     * @param string $domain Domain to verify.
     * @param string $token Challenge token.
     * @param string $expectedPayload Expected payload.
     *
     * @return Promise Resolves successfully if the challenge has been successfully verified, otherwise fails.
     * @throws AcmeException If the challenge could not be verified.
     */
    public function verifyChallenge(string $domain, string $token, string $expectedPayload): Promise {
        return call(function () use ($domain, $token, $expectedPayload) {
            $uri = "http://{$domain}/.well-known/acme-challenge/{$token}";

            /** @var Response $response */
            $response = yield $this->client->request($uri);

            /** @var string $body */
            $body = yield $response->getBody();

            if (rtrim($expectedPayload) !== rtrim($body)) {
                throw new AcmeException("Verification failed, please check the response body for '{$uri}'. It contains '{$body}' but '{$expectedPayload}' was expected.");
            }
        });
    }
}