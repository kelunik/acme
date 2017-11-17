<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\Backend\OpensslBackend;
use Kelunik\Acme\Crypto\PrivateKey;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;

class KeyAuthorizationTest extends TestCase {
    /**
     * @test
     * @expectedException \TypeError
     * @expectedExceptionMessage must be of the type string
     */
    public function failsIfTokenNotString() {
        $keyPair = (new RsaKeyGenerator)->generateKey();
        generateKeyAuthorization($keyPair, null, new OpensslBackend);
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Couldn't read private key.
     */
    public function failsWithInvalidKey() {
        $keyPair = new PrivateKey('abc');
        generateKeyAuthorization($keyPair, 'foobar', new OpensslBackend);
    }

    /**
     * @test
     */
    public function containsTokenOnSuccess() {
        $token = 'some-random-token';
        $keyPair = (new RsaKeyGenerator)->generateKey();
        $payload = generateKeyAuthorization($keyPair, $token, new OpensslBackend);
        $this->assertStringStartsWith($token . '.', $payload);
    }
}