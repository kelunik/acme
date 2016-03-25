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
     * @var \Kelunik\Acme\AcmeService
     */
    private $acme;

    public function setUp() {
        \Amp\reactor(\Amp\driver());

        $this->resolver = $this->getMockBuilder(Resolver::class)->getMock();
        \Amp\Dns\resolver($this->resolver);

        $keyPair = (new OpenSSLKeyGenerator())->generate();
        $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
        $this->acme = new AcmeService($client);
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Verification failed, no TXT record found for '_acme-challenge.example.com'.
     */
    public function failsOnDnsNotFound() {
        $this->resolver->method("query")->willReturn(new Failure(new NoRecordException));
        \Amp\wait($this->acme->verifyDns01Challenge("example.com", "foobar"));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Verification failed, couldn't query TXT record of '_acme-challenge.example.com'
     */
    public function failsOnGeneralDnsIssue() {
        $this->resolver->method("query")->willReturn(new Failure(new ResolutionException));
        \Amp\wait($this->acme->verifyDns01Challenge("example.com", "foobar"));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Verification failed, please check DNS record under '_acme-challenge.example.com'.
     */
    public function failsOnWrongPayload() {
        $this->resolver->method("query")->willReturn(new Success([["xyz", Record::TXT, 300]]));
        \Amp\wait($this->acme->verifyDns01Challenge("example.com", "foobar"));
    }

    /**
     * @test
     */
    public function succeedsOnRightPayload() {
        $this->resolver->method("query")->willReturn(new Success([["foobar", Record::TXT, 300]]));
        \Amp\wait($this->acme->verifyDns01Challenge("example.com", "foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function failsWithDomainNotString() {
        \Amp\wait($this->acme->verifyDns01Challenge(null, ""));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function failsWithPayloadNotString() {
        \Amp\wait($this->acme->verifyDns01Challenge("example.com", null));
    }
}