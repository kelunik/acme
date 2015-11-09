<?php

namespace Kelunik\Acme;

use Amp\Promise;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
interface AcmeAdapter {
    /**
     * Implementation MUST provide an absolute path where the certificate for $dns is / will be stored.
     *
     * @param string $dns FQDN
     * @return Promise
     */
    public function getCertificatePath(string $dns): Promise;

    /**
     * Implementation MUST provide the $payload on /.well-known/acme-challenge/$token and the returned promise MUST NOT
     * be resolved until the payload is provided.
     *
     * @param string $dns FQDN
     * @param string $token Token is guaranteed to contain only base64 url-safe characters.
     * @param string $payload JWT payload, which must be provided as response body.
     * @return Promise
     */
    public function provideChallenge(string $dns, string $token, string $payload): Promise;
}