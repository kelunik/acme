<?php

namespace Kelunik\Acme;

use Amp\Socket\ClientSocket;
use PHPUnit\Framework\TestCase;

class ConnectTest extends TestCase {
    /**
     * Test that TLS connections to the ACME server succeed.
     * See https://github.com/amphp/socket/releases/tag/v0.9.6 for reasons.
     *
     * @dataProvider provideCryptoConnectArgs
     */
    public function testCryptoConnect($uri) {
        $promise = \Amp\Socket\cryptoConnect($uri);
        $sock = \Amp\Promise\wait($promise);
        $this->assertInstanceOf(ClientSocket::class, $sock);
    }

    public function provideCryptoConnectArgs() {
        return [
            ['acme-v01.api.letsencrypt.org:443'],
            ['acme-staging.api.letsencrypt.org:443'],
        ];
    }
}
