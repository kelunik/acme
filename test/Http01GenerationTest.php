<?php

namespace Kelunik\Acme;

class Http01GenerationTest extends \PHPUnit_Framework_TestCase {
    /**
     * @var AcmeService
     */
    private $acme;

    public function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());

        $keyPair = (new OpenSSLKeyGenerator)->generate();
        $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
        $this->acme = new AcmeService($client);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage token must be of type string
     */
    public function failsIfTokenNotString() {
        $keyPair = (new OpenSSLKeyGenerator)->generate();
        $this->acme->generateHttp01Payload($keyPair, null);
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Couldn't read private key.
     */
    public function failsWithInvalidKey() {
        $keyPair = new KeyPair("abc", "def");
        $this->acme->generateHttp01Payload($keyPair, "foobar");
    }

    /**
     * @test
     */
    public function containsTokenOnSuccess() {
        $token = "some-random-token";
        $keyPair = (new OpenSSLKeyGenerator)->generate();
        $payload = $this->acme->generateHttp01Payload($keyPair, $token);
        $this->assertStringStartsWith($token . ".", $payload);
    }
}