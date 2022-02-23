<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Verifiers;

use Amp\Http\Client\Connection\DefaultConnectionFactory;
use Amp\Http\Client\Connection\UnlimitedConnectionPool;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\Promise;
use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use Kelunik\Acme\AcmeException;
use function Amp\call;

/**
 * Verifies HTTP-01 challenges.
 *
 * @package Kelunik\Acme
 */
final class Http01
{
    private $httpClient;

    /**
     * Http01 constructor.
     *
     * @param HttpClient|null $httpClient HTTP client to use, otherwise a default client will be used.
     */
    public function __construct(?HttpClient $httpClient = null)
    {
        $this->httpClient = $httpClient ?? (new HttpClientBuilder)->usingPool(new UnlimitedConnectionPool(new DefaultConnectionFactory(
            null,
            (new ConnectContext)->withTlsContext((new ClientTlsContext(''))->withoutPeerVerification())
        )))->build();
    }

    /**
     * Verifies a HTTP-01 challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @param string $domain Domain to verify.
     * @param string $token Challenge token.
     * @param string $expectedPayload Expected payload.
     *
     * @return void Resolves successfully if the challenge has been successfully verified, otherwise fails.
     * @throws AcmeException If the challenge could not be verified.
     * @api
     */
    public function verifyChallenge(string $domain, string $token, string $expectedPayload): void
    {
        $uri = "http://{$domain}/.well-known/acme-challenge/{$token}";

        $response = $this->httpClient->request(new Request($uri));

        $body = $response->getBody()->buffer();

        if (\rtrim($expectedPayload) !== \rtrim($body)) {
            throw new AcmeException("Verification failed, please check the response body for '{$uri}'. It contains '{$body}' but '{$expectedPayload}' was expected.");
        }
    }
}
