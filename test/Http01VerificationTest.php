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
    public function ignoresWrongPeerName(): void
    {
        self::markTestSkipped('Currently skipped as configuration is not in place for it.');

        $payloadResponse = HttpClientBuilder::buildDefault()->request('http://blog.kelunik.com/robots.txt');
        $payload = \trim($payloadResponse->getBody());

        $this->verifier->verifyChallenge('kelunik.com', 'invalid-common-name', $payload);
    }

    /**
     * @test
     */
    public function failsOnWrongPayload(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Verification failed');

        $this->verifier->verifyChallenge('kelunik.com', 'abcdef', 'foobar');
    }
}
