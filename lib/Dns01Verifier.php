<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\CoroutineResult;
use Amp\Dns\NoRecordException;
use Amp\Dns\Record;
use Amp\Dns\ResolutionException;
use Amp\Dns\Resolver;
use InvalidArgumentException;

/**
 * Verifies DNS-01 challenges.
 *
 * @package Kelunik\Acme
 */
class Dns01Verifier {
    /** @var Resolver */
    private $resolver;

    public function __construct(Resolver $resolver = null) {
        $this->resolver = $resolver ?: \Amp\Dns\resolver();
    }

    /**
     * Verifies a DNS-01 Challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @api
     * @param string $domain domain to verify
     * @param string $keyAuthorization key authorization (expected payload)
     * @return \Amp\Promise resolves to the DNS entry found
     * @throws AcmeException If the challenge could not be verified.
     */
    public function verifyChallenge($domain, $keyAuthorization) {
        return \Amp\resolve($this->doVerifyChallenge($domain, $keyAuthorization));
    }

    /**
     * Verifies a DNS-01 Challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @param string $domain domain to verify
     * @param string $keyAuthorization key authorization (expected payload)
     * @return \Generator coroutine resolved to the DNS entry found
     * @throws AcmeException If the challenge could not be verified.
     */
    private function doVerifyChallenge($domain, $keyAuthorization) {
        if (!is_string($domain)) {
            throw new InvalidArgumentException(sprintf("\$domain must be of type string, %s given.", gettype($domain)));
        }

        if (!is_string($keyAuthorization)) {
            throw new InvalidArgumentException(sprintf("\$keyAuthorization must be of type string, %s given.", gettype($keyAuthorization)));
        }

        $uri = "_acme-challenge." . $domain;

        try {
            $dnsResponse = (yield $this->resolver->query($uri, ["types" => Record::TXT]));
        } catch (NoRecordException $e) {
            throw new AcmeException("Verification failed, no TXT record found for '{$uri}'.", 0, $e);
        } catch (ResolutionException $e) {
            throw new AcmeException("Verification failed, couldn't query TXT record of '{$uri}': " . $e->getMessage(), 0, $e);
        }

        list($record) = $dnsResponse;
        list($payload) = $record;

        if ($payload !== $keyAuthorization) {
            throw new AcmeException("Verification failed, please check DNS record under '{$uri}'. Expected: '{$keyAuthorization}', Got: '{$payload}'.");
        }

        yield new CoroutineResult($dnsResponse);
        return;
    }
}