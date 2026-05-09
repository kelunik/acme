<?php declare(strict_types=1);

namespace Kelunik\Acme;

use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use PHPUnit\Framework\TestCase;
use function Amp\Socket\connect;

final class ConnectTest extends TestCase
{
    /**
     * Test that TLS connections to the ACME server succeed.
     * See https://github.com/amphp/socket/releases/tag/v0.9.6 for reasons.
     *
     * @dataProvider provideCryptoConnectArgs
     */
    public function testCryptoConnect(string $uri): void
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
