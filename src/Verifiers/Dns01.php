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
    /** @var Dns\DnsResolver */
    private $resolver;

    /**
     * Dns01 constructor.
     *
     * @param Dns\DnsResolver|null $resolver DNS resolver, otherwise a default resolver will be used.
     */
    public function __construct(Dns\DnsResolver $resolver = null)
    {
        $this->resolver = $resolver ?? Dns\dnsResolver();
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
            $dnsRecords = $this->resolver->query($uri, Dns\DnsRecord::TXT);
        } catch (Dns\MissingDnsRecordException $e) {
            throw new AcmeException("Verification failed, no TXT record found for '{$uri}'.", (string) ($e->getCode() ?? 404), $e);
        } catch (Dns\DnsException $e) {
            throw new AcmeException(
                "Verification failed, couldn't query TXT record of '{$uri}': " . $e->getMessage(),
                (string) ($e->getCode() ?? 500),
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
