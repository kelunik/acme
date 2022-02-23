<?php

namespace Kelunik\Acme;

use Amp\Dns\DnsException;
use Amp\Dns\NoRecordException;
use Amp\Dns\Record;
use Amp\Dns\Resolver;
use Amp\Failure;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Success;

class Dns01VerificationTest extends AsyncTestCase
{
    private $resolver;

    /**
     * @var Verifiers\Dns01
     */
    private $verifier;

    public function setUp(): void
    {
        parent::setUp();

        $this->resolver = $this->getMockBuilder(Resolver::class)->getMock();
        $this->verifier = new Verifiers\Dns01($this->resolver);
    }

    /**
     * @test
     */
    public function failsOnDnsNotFound(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Verification failed, no TXT record found for \'_acme-challenge.example.com\'.');

        $this->resolver->method("query")->willThrowException(new NoRecordException);
        $this->verifier->verifyChallenge("example.com", "foobar");
    }

    /**
     * @test
     */
    public function failsOnGeneralDnsIssue(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Verification failed, couldn\'t query TXT record of \'_acme-challenge.example.com\'');

        $this->resolver->method("query")->willThrowException(new DnsException);
        $this->verifier->verifyChallenge("example.com", "foobar");
    }

    /**
     * @test
     */
    public function failsOnWrongPayload(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage("Verification failed, please check DNS record for '_acme-challenge.example.com'.");

        $this->resolver->method("query")->willReturn([new Record("xyz", Record::TXT, 300)]);
        $this->verifier->verifyChallenge("example.com", "foobar");
    }

    /**
     * @test
     */
    public function succeedsOnRightPayload(): void
    {
        $this->expectNotToPerformAssertions();

        $this->resolver->method("query")->willReturn([new Record("foobar", Record::TXT, 300)]);
        $this->verifier->verifyChallenge("example.com", "foobar");
    }

    /**
     * @test
     */
    public function failsWithDomainNotString(): void
    {
        $this->expectException(\TypeError::class);

        $this->verifier->verifyChallenge(null, "");
    }

    /**
     * @test
     */
    public function failsWithPayloadNotString(): void
    {
        $this->expectException(\TypeError::class);

        $this->verifier->verifyChallenge("example.com", null);
    }
}
