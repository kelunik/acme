<?php

namespace Kelunik\Acme;

class KeyAuthorizationTest extends \PHPUnit_Framework_TestCase {
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage token must be of type string
     */
    public function failsIfTokenNotString() {
        $keyPair = (new OpenSSLKeyGenerator)->generate();
        generateKeyAuthorization($keyPair, null);
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Couldn't read private key.
     */
    public function failsWithInvalidKey() {
        $keyPair = new KeyPair("abc", "def");
        generateKeyAuthorization($keyPair, "foobar");
    }

    /**
     * @test
     */
    public function containsTokenOnSuccess() {
        $token = "some-random-token";
        $keyPair = (new OpenSSLKeyGenerator)->generate();
        $payload = generateKeyAuthorization($keyPair, $token);
        $this->assertStringStartsWith($token . ".", $payload);
    }
}