<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Domain\Registration;
use PHPUnit\Framework\TestCase;

class RegistrationTest extends TestCase {
    /**
     * @param string $location URI of the registration object
     * @param $status
     * @param array $contact all contacts registered with the server
     * @param null $orders
     * @dataProvider provideSuccessArgs
     * @test
     */
    public function success($location, $status, array $contact = [], $orders = null) {
        $reg = new Registration($location, $status, $contact, $orders);

        $this->assertSame($location, $reg->getLocation());
        $this->assertSame($contact, $reg->getContact());
        $this->assertSame($status, $reg->getStatus());
        $this->assertSame($orders, $reg->getOrders());
    }

    public function provideSuccessArgs() {
        $server = 'https://acme-v02.api.letsencrypt.org/directory';

        return [
            [$server, "ready"],
            [$server, "ready", []],
            [$server, "ready", ['mailto:me@example.com']],
            [$server, "ready", ['mailto:me@example.com'], null],
            [$server, "ready", ['mailto:me@example.com'], "{$server}/orders"],
        ];
    }
}
