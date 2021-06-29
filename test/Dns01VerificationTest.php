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
    public function failsOnDnsNotFound(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Verification failed, no TXT record found for \'_acme-challenge.example.com\'.');

        $this->resolver->method("query")->willReturn(new Failure(new NoRecordException));
        yield $this->verifier->verifyChallenge("example.com", "foobar");
    }

    /**
     * @test
     */
    public function failsOnGeneralDnsIssue(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Verification failed, couldn\'t query TXT record of \'_acme-challenge.example.com\'');

        $this->resolver->method("query")->willReturn(new Failure(new DnsException));
        yield $this->verifier->verifyChallenge("example.com", "foobar");
    }

    /**
     * @test
     */
    public function failsOnWrongPayload(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage("Verification failed, please check DNS record for '_acme-challenge.example.com'.");

        $this->resolver->method("query")->willReturn(new Success([new Record("xyz", Record::TXT, 300)]));
        yield $this->verifier->verifyChallenge("example.com", "foobar");
    }

    /**
     * @test
     */
    public function succeedsOnRightPayload(): \Generator
    {
        $this->expectNotToPerformAssertions();

        $this->resolver->method("query")->willReturn(new Success([new Record("foobar", Record::TXT, 300)]));
        yield $this->verifier->verifyChallenge("example.com", "foobar");
    }

    /**
     * @test
     */
    public function failsWithDomainNotString(): \Generator
    {
        $this->expectException(\TypeError::class);

        yield $this->verifier->verifyChallenge(null, "");
    }

    /**
     * @test
     */
    public function failsWithPayloadNotString(): \Generator
    {
        $this->expectException(\TypeError::class);

        yield $this->verifier->verifyChallenge("example.com", null);
    }
}
