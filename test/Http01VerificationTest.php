<?php

namespace Kelunik\Acme;

use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Response;
use Amp\PHPUnit\AsyncTestCase;

class Http01VerificationTest extends AsyncTestCase
{
    /**
     * @var Verifiers\Http01
     */
    private $verifier;

    public function setUp(): void
    {
        parent::setUp();

        $this->verifier = new Verifiers\Http01();
    }

    /**
     * @test
     */
    public function ignoresWrongPeerName(): \Generator
    {
        self::markTestSkipped('Currently skipped as configuration is not in place for it.');

        /** @var Response $payloadResponse */
        $payloadResponse = yield HttpClientBuilder::buildDefault()->request('http://blog.kelunik.com/robots.txt');
        $payload = \trim($payloadResponse->getBody());

        yield $this->verifier->verifyChallenge('kelunik.com', 'invalid-common-name', $payload);
    }

    /**
     * @test
     */
    public function failsOnWrongPayload(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Verification failed');

        yield $this->verifier->verifyChallenge('kelunik.com', 'abcdef', 'foobar');
    }
}
