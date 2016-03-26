<?php

namespace Kelunik\Acme;

use Amp\Artax\Response;
use Amp\Dns\NoRecordException;
use Amp\Dns\Record;
use Amp\Dns\ResolutionException;
use Amp\Dns\Resolver;
use Amp\Failure;
use Amp\Success;

class Dns01VerificationTest extends \PHPUnit_Framework_TestCase {
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $resolver;

    /**
     * @var Dns01Verifier
     */
    private $verifier;

    public function setUp() {
        \Amp\reactor(\Amp\driver());

        $this->resolver = $this->getMockBuilder(Resolver::class)->getMock();
        $this->verifier = new Dns01Verifier($this->resolver);
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Verification failed, no TXT record found for '_acme-challenge.example.com'.
     */
    public function failsOnDnsNotFound() {
        $this->resolver->method("query")->willReturn(new Failure(new NoRecordException));
        \Amp\wait($this->verifier->verifyChallenge("example.com", "foobar"));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Verification failed, couldn't query TXT record of '_acme-challenge.example.com'
     */
    public function failsOnGeneralDnsIssue() {
        $this->resolver->method("query")->willReturn(new Failure(new ResolutionException));
        \Amp\wait($this->verifier->verifyChallenge("example.com", "foobar"));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Verification failed, please check DNS record under '_acme-challenge.example.com'.
     */
    public function failsOnWrongPayload() {
        $this->resolver->method("query")->willReturn(new Success([["xyz", Record::TXT, 300]]));
        \Amp\wait($this->verifier->verifyChallenge("example.com", "foobar"));
    }

    /**
     * @test
     */
    public function succeedsOnRightPayload() {
        $this->resolver->method("query")->willReturn(new Success([["foobar", Record::TXT, 300]]));
        \Amp\wait($this->verifier->verifyChallenge("example.com", "foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function failsWithDomainNotString() {
        \Amp\wait($this->verifier->verifyChallenge(null, ""));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function failsWithPayloadNotString() {
        \Amp\wait($this->verifier->verifyChallenge("example.com", null));
    }
}