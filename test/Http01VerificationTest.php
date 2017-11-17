<?php

namespace Kelunik\Acme;

use Amp\Artax\DefaultClient;
use Amp\Artax\Response;
use PHPUnit\Framework\TestCase;

class Http01VerificationTest extends TestCase {
    /**
     * @var Verifiers\Http01
     */
    private $verifier;

    public function setUp() {
        $this->verifier = new Verifiers\Http01();
    }

    /**
     * @test
     */
    public function ignoresWrongPeerName() {
        $this->markTestSkipped('Currently skipped as configuration is not in place for it.');

        /** @var Response $payloadResponse */
        $payloadResponse = \Amp\Promise\wait((new DefaultClient)->request('http://blog.kelunik.com/robots.txt'));
        $payload = trim($payloadResponse->getBody());

        \Amp\Promise\wait($this->verifier->verifyChallenge('kelunik.com', 'invalid-common-name', $payload));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Verification failed
     */
    public function failsOnWrongPayload() {
        \Amp\Promise\wait($this->verifier->verifyChallenge('kelunik.com', 'abcdef', 'foobar'));
    }

    /**
     * @test
     * @expectedException \TypeError
     * @expectedExceptionMessage must be of the type string
     */
    public function failsIfDomainNotString() {
        \Amp\Promise\wait($this->verifier->verifyChallenge(null, 'abcdef', 'foobar'));
    }

    /**
     * @test
     * @expectedException \TypeError
     * @expectedExceptionMessage must be of the type string
     */
    public function failsIfTokenNotString() {
        \Amp\Promise\wait($this->verifier->verifyChallenge('kelunik.com', null, 'foobar'));
    }

    /**
     * @test
     * @expectedException \TypeError
     * @expectedExceptionMessage must be of the type string
     */
    public function failsIfPayloadNotString() {
        \Amp\Promise\wait($this->verifier->verifyChallenge('kelunik.com', 'abcdef', null));
    }
}
