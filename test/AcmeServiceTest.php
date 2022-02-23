<?php

namespace Kelunik\Acme;

use Amp\Http\Client\Connection\DefaultConnectionFactory;
use Amp\Http\Client\Connection\UnlimitedConnectionPool;
use Amp\Http\Client\HttpClientBuilder;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use Kelunik\Acme\Protocol\Account;

class AcmeServiceTest extends AsyncTestCase
{
    private AcmeService $service;

    public function setUp(): void
    {
        parent::setUp();

        if (\getenv('BOULDER_HOST') === false) {
            $this->markTestSkipped('No Boulder host set. Set the environment variable BOULDER_HOST to enable those tests.');
        }

        $httpPool = new UnlimitedConnectionPool(new DefaultConnectionFactory(
            null,
            (new ConnectContext)->withTlsContext((new ClientTlsContext(''))->withoutPeerVerification())
        ));

        $httpClient = (new HttpClientBuilder)
            ->usingPool($httpPool)
            ->build();

        $key = (new RsaKeyGenerator)->generateKey();
        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/dir', $key, $httpClient);
        $this->service = new AcmeService($client);
    }

    /**
     * @test
     */
    public function registerNotAgreeTOS(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Provided account did not agree to the terms of service');

        $this->service->register('me@example.com');
    }

    /**
     * @test
     */
    public function registerAndReRegisterGivesSameLocation(): void
    {
        /** @var Account $account */
        $account = $this->service->register('me@example.com', true);
        $this->assertSame('mailto:me@example.com', (string) $account->getContacts()[0]);
        $this->assertNotNull($l1 = (string) $account->getUrl());

        /** @var Account $account */
        $account = $this->service->register('me@example.com', true);
        $this->assertSame('mailto:me@example.com', (string) $account->getContacts()[0]);
        $this->assertNotNull($l2 = (string) $account->getUrl());

        $this->assertSame($l1, $l2);
    }
}
