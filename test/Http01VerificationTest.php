<?php declare(strict_types=1);

namespace Kelunik\Acme;

use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use PHPUnit\Framework\TestCase;

final class Http01VerificationTest extends TestCase
{
    /**
     * @var Verifiers\Http01
     */
    private $verifier;

    #[\Override]
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

        $payloadResponse = HttpClientBuilder::buildDefault()->request(new Request('http://blog.kelunik.com/robots.txt'));
        $payload = \trim($payloadResponse->getBody()->buffer());

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
