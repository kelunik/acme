<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Verifiers;

use Amp\Dns;
use Kelunik\Acme\AcmeException;

/**
 * Verifies DNS-01 challenges.
 *
 * @package Kelunik\Acme
 */
final class Dns01
{
    /** @var Dns\Resolver */
    private $resolver;

    /**
     * Dns01 constructor.
     *
     * @param Dns\Resolver|null $resolver DNS resolver, otherwise a default resolver will be used.
     */
    public function __construct(Dns\Resolver $resolver = null)
    {
        $this->resolver = $resolver ?? Dns\resolver();
    }

    /**
     * Verifies a DNS-01 Challenge.
     *
     * Can be used to verify a challenge before requesting validation from a CA to catch errors early.
     *
     * @param string $domain domain to verify
     * @param string $expectedPayload expected DNS record value
     *
     * @return void Resolves successfully if the challenge has been successfully verified, otherwise fails.
     * @throws AcmeException If the challenge could not be verified.
     * @api
     */
    public function verifyChallenge(string $domain, string $expectedPayload): void
    {
        $uri = '_acme-challenge.' . $domain;

        try {
            $dnsRecords = $this->resolver->query($uri, Dns\Record::TXT);
        } catch (Dns\NoRecordException $e) {
            throw new AcmeException("Verification failed, no TXT record found for '{$uri}'.", 0, $e);
        } catch (Dns\DnsException $e) {
            throw new AcmeException(
                "Verification failed, couldn't query TXT record of '{$uri}': " . $e->getMessage(),
                0,
                $e
            );
        }

        $values = [];

        foreach ($dnsRecords as $dnsRecord) {
            $values[] = $dnsRecord->getValue();
        }

        if (!\in_array($expectedPayload, $values, true)) {
            $values = "'" . \implode("', '", $values) . "'";
            throw new AcmeException("Verification failed, please check DNS record for '{$uri}'. It contains {$values} but '{$expectedPayload}' was expected.");
        }
    }
}
