<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\Response;

class Http01VerificationTest extends \PHPUnit_Framework_TestCase {
    /**
     * @var AcmeService
     */
    private $acme;

    public function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());

        $keyPair = (new OpenSSLKeyGenerator())->generate();
        $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
        $this->acme = new AcmeService($client);
    }

    /**
     * @test
     */
    public function ignoresWrongPeerName() {
        /** @var Response $payloadResponse */
        $payloadResponse = \Amp\wait((new Client)->request("http://blog.kelunik.com/robots.txt"));
        $payload = trim($payloadResponse->getBody());

        \Amp\wait($this->acme->verifyHttp01Challenge("kelunik.com", "invalid-common-name", $payload));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage selfVerify failed
     */
    public function failsOnWrongPayload() {
        \Amp\wait($this->acme->verifyHttp01Challenge("kelunik.com", "abcdef", "foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage domain must be of type string
     */
    public function failsIfDomainNotString() {
        \Amp\wait($this->acme->verifyHttp01Challenge(null, "abcdef", "foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage token must be of type string
     */
    public function failsIfTokenNotString() {
        \Amp\wait($this->acme->verifyHttp01Challenge("kelunik.com", null, "foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage payload must be of type string
     */
    public function failsIfPayloadNotString() {
        \Amp\wait($this->acme->verifyHttp01Challenge("kelunik.com", "abcdef", null));
    }
}
