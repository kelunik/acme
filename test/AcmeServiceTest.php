<?php

namespace Kelunik\Acme;

use Amp\Http\Client\Connection\DefaultConnectionFactory;
use Amp\Http\Client\Connection\UnlimitedConnectionPool;
use Amp\Http\Client\HttpClientBuilder;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use Kelunik\Acme\Domain\Registration;

class AcmeServiceTest extends AsyncTestCase
{
    /**
     * @var AcmeService
     */
    private $acme;

    public function setUp(): void
    {
        parent::setUp();

        if (\getenv('BOULDER_HOST') === false) {
            $this->markTestSkipped('No Boulder host set. Set the environment variable BOULDER_HOST to enable those tests.');
        }

        $httpPool = new UnlimitedConnectionPool(new DefaultConnectionFactory(null,
            (new ConnectContext)->withTlsContext((new ClientTlsContext(''))->withoutPeerVerification())));

        $httpClient = (new HttpClientBuilder)
            ->usingPool($httpPool)
            ->build();

        $key = (new RsaKeyGenerator)->generateKey();
        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/dir', $key, null, $httpClient);
        $this->acme = new AcmeService($client);
    }

    /**
     * @test
     */
    public function registerNotAgreeTOS(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Provided account did not agree to the terms of service');

        /** @var Registration $registration */
        yield $this->acme->register('me@example.com');
    }

    /**
     * @test
     */
    public function registerAndReRegisterGivesSameLocation(): \Generator
    {
        $registration = yield $this->acme->register('me@example.com', true);
        $this->assertSame(['mailto:me@example.com'], $registration->getContact());
        $this->assertNotNull($l1 = $registration->getLocation());

        $registration = yield $this->acme->register('me@example.com', true);
        $this->assertSame(['mailto:me@example.com'], $registration->getContact());
        $this->assertNotNull($l2 = $registration->getLocation());

        $this->assertSame($l1, $l2);
    }
}
