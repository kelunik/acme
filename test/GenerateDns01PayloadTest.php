<?php declare(strict_types=1);

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\Backend\OpensslBackend;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;

final class GenerateDns01PayloadTest extends TestCase
{
    public function testGenerateDns01Payload(): void
    {
        $keyAuth = generateKeyAuthorization((new RsaKeyGenerator)->generateKey(), "foobar", new OpensslBackend);
        $dnsPayload = generateDns01Payload($keyAuth);

        $expected = \hash('sha256', $keyAuth, true);
        $expected = base64UrlEncode($expected);

        $this->assertSame($expected, $dnsPayload);
    }
}
