<?php

namespace Kelunik\Acme;

use Amp\PHPUnit\AsyncTestCase;
use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use function Amp\Socket\connect;

class ConnectTest extends AsyncTestCase
{
    /**
     * Test that TLS connections to the ACME server succeed.
     * See https://github.com/amphp/socket/releases/tag/v0.9.6 for reasons.
     *
     * @dataProvider provideCryptoConnectArgs
     */
    public function testCryptoConnect($uri): void
    {
        $this->expectNotToPerformAssertions();

        $context = (new ConnectContext)->withTlsContext(new ClientTlsContext(\parse_url($uri, \PHP_URL_HOST)));

        $sock = connect($uri, $context);
        $sock->setupTls();
    }

    public function provideCryptoConnectArgs(): iterable
    {
        yield ['acme-v02.api.letsencrypt.org:443'];
        yield ['acme-staging-v02.api.letsencrypt.org:443'];
    }
}
