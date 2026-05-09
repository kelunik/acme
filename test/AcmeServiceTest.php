<?php declare(strict_types=1);

namespace Kelunik\Acme;

use Amp\Http\Client\Connection\DefaultConnectionFactory;
use Amp\Http\Client\Connection\UnlimitedConnectionPool;
use Amp\Http\Client\HttpClientBuilder;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use Kelunik\Acme\Csr\OpensslCsrGenerator;
use Kelunik\Acme\Protocol\Authorization;
use Kelunik\Acme\Protocol\Challenge;

final class AcmeServiceTest extends AsyncTestCase
{
    private AcmeService $service;

    #[\Override]
    public function setUp(): void
    {
        parent::setUp();

        if (\getenv('PEBBLE_HOST') === false) {
            $this->markTestSkipped('No pebble host set. Set the environment variable PEBBLE_HOST to enable those tests.');
        }

        $httpPool = new UnlimitedConnectionPool(new DefaultConnectionFactory(
            null,
            (new ConnectContext)->withTlsContext((new ClientTlsContext(''))->withoutPeerVerification())
        ));

        $httpClient = (new HttpClientBuilder)
            ->usingPool($httpPool)
            ->build();

        $key = (new RsaKeyGenerator)->generateKey();
        $client = new AcmeClient(\getenv('PEBBLE_HOST') . '/dir', $key, $httpClient);
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
        $account = $this->service->register('me@example.com', true);
        $this->assertSame('mailto:me@example.com', (string) $account->getContacts()[0]);
        $this->assertNotEmpty($l1 = (string) $account->getUrl());

        $account = $this->service->register('me@example.com', true);
        $this->assertSame('mailto:me@example.com', (string) $account->getContacts()[0]);
        $this->assertNotEmpty($l2 = (string) $account->getUrl());

        $this->assertSame($l1, $l2);
    }

    /**
     * @test
     */
    public function issuance(): void
    {
        $domains = ['example.com'];

        $this->service->register(null, true);
        $order = $this->service->newOrder($domains);

        foreach ($order->getAuthorizationUrls() as $authorizationUrl) {
            $authorization = $this->service->getAuthorization($authorizationUrl);

            if ($authorization->getIdentifier()->getType() !== 'dns') {
                throw new AcmeException('Invalid identifier: ' . $authorization->getIdentifier()->getType());
            }

            $httpChallenge = $this->findHttpChallenge($authorization);

            $this->service->finalizeChallenge($httpChallenge->getUrl());
            $this->service->pollForAuthorization($authorization->getUrl());
        }

        $this->service->pollForOrderReady($order->getUrl());

        $key = (new RsaKeyGenerator(2048))->generateKey();
        $csr = (new OpensslCsrGenerator)->generateCsr($key, $domains);

        $this->service->finalizeOrder($order->getFinalizationUrl(), $csr);
        $this->service->pollForOrderValid($order->getUrl());

        $order = $this->service->getOrder($order->getUrl());

        $certificates = $this->service->downloadCertificates($order->getCertificateUrl());

        self::assertCount(2, $certificates);
        self::assertEquals('example.com', $certificates[0]->getSubject()->getCommonName(), $certificates[0]->toPem());
        self::assertStringStartsWith('Pebble Intermediate CA', $certificates[1]->getSubject()->getCommonName(), $certificates[0]->toPem());
    }

    private function findHttpChallenge(Authorization $authorization): ?Challenge
    {
        $challenges = $authorization->getChallenges();

        foreach ($challenges as $challenge) {
            if ($challenge->getType() === 'http-01') {
                return $challenge;
            }
        }

        return null;
    }
}
