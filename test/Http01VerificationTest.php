<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\Response;

class Http01VerificationTest extends \PHPUnit_Framework_TestCase {
    /**
     * @var Verifiers\Http01
     */
    private $verifier;

    public function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());

        $this->verifier = new Verifiers\Http01();
    }

    /**
     * @test
     */
    public function ignoresWrongPeerName() {
        $this->markTestSkipped("Currently skipped as configuration is not in place for it.");

        /** @var Response $payloadResponse */
        $payloadResponse = \Amp\wait((new Client)->request("http://blog.kelunik.com/robots.txt"));
        $payload = trim($payloadResponse->getBody());

        \Amp\wait($this->verifier->verifyChallenge("kelunik.com", "invalid-common-name", $payload));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage selfVerify failed
     */
    public function failsOnWrongPayload() {
        \Amp\wait($this->verifier->verifyChallenge("kelunik.com", "abcdef", "foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage domain must be of type string
     */
    public function failsIfDomainNotString() {
        \Amp\wait($this->verifier->verifyChallenge(null, "abcdef", "foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage token must be of type string
     */
    public function failsIfTokenNotString() {
        \Amp\wait($this->verifier->verifyChallenge("kelunik.com", null, "foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage payload must be of type string
     */
    public function failsIfPayloadNotString() {
        \Amp\wait($this->verifier->verifyChallenge("kelunik.com", "abcdef", null));
    }
}
