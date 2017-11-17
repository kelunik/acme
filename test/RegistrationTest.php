<?php

namespace Kelunik\Acme;

use PHPUnit\Framework\TestCase;

class RegistrationTest extends TestCase {
    /**
     * @param string      $location URI of the registration object
     * @param array       $contact all contacts registered with the server
     * @param string|null $agreement URI to the agreement, if agreed
     * @param string      $authorizations URI to retrieve authorizations
     * @param string      $certificates URI to retrieve certificates
     *
     * @dataProvider provideSuccessArgs
     * @test
     */
    public function success($location, array $contact = [], $agreement = null, $authorizations = null, $certificates = null) {
        $reg = new Registration($location, $contact, $agreement, $authorizations, $certificates);

        $this->assertSame($location, $reg->getLocation());
        $this->assertSame($contact, $reg->getContact());
        $this->assertSame($agreement, $reg->getAgreement());
        $this->assertSame($authorizations, $reg->getAuthorizations());
        $this->assertSame($certificates, $reg->getCertificates());
    }

    public function provideSuccessArgs() {
        $server = 'https://acme-v01.api.letsencrypt.org/directory';

        return [
            [$server],
            [$server, []],
            [$server, ['mailto:me@example.com']],
            [$server, ['mailto:me@example.com'], null, "{$server}/authz"],
            [$server, ['mailto:me@example.com'], null, "{$server}/authz", "{$server}/certs"],
            [$server, ['mailto:me@example.com'], "{$server}/tos", "{$server}/authz", "{$server}/certs"],
        ];
    }
}
