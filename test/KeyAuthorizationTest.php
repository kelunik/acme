<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\Backend\OpensslBackend;
use Kelunik\Acme\Crypto\PrivateKey;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;

class KeyAuthorizationTest extends TestCase
{
    /**
     * @test
     */
    public function failsWithInvalidKey(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage("Couldn't read private key.");

        $keyPair = new PrivateKey('abc');
        generateKeyAuthorization($keyPair, 'foobar', new OpensslBackend);
    }

    /**
     * @test
     */
    public function containsTokenOnSuccess(): void
    {
        $token = 'some-random-token';
        $keyPair = (new RsaKeyGenerator)->generateKey();
        $payload = generateKeyAuthorization($keyPair, $token, new OpensslBackend);
        $this->assertStringStartsWith($token . '.', $payload);
    }
}
