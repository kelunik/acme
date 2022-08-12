<?php

namespace Kelunik\Acme;

use Amp\ByteStream\ReadableBuffer;
use Amp\Cancellation;
use Amp\Dns\NoRecordException;
use Amp\Dns\Resolver;
use Amp\Http\Client\ApplicationInterceptor;
use Amp\Http\Client\Connection\DefaultConnectionFactory;
use Amp\Http\Client\Connection\UnlimitedConnectionPool;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use ReflectionClass;
use function Amp\Dns\createDefaultResolver;
use function Amp\Dns\resolver;

class AcmeClientTest extends AsyncTestCase
{
    /** @var UnlimitedConnectionPool */
    private $httpPool;

    public function setUp(): void
    {
        parent::setUp();

        $this->httpPool = new UnlimitedConnectionPool(new DefaultConnectionFactory(
            null,
            (new ConnectContext)->withTlsContext((new ClientTlsContext(''))->withoutPeerVerification())
        ));
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        resolver(createDefaultResolver());
    }

    /**
     * @test
     */
    public function pebbleConfigured(): void
    {
        if (\getenv('PEBBLE_HOST') === false) {
            $this->markTestSkipped('No pebble host set. Set the environment variable PEBBLE_HOST to enable those tests.');
        }

        $this->assertTrue(true);
    }

    /**
     * @test
     * @depends pebbleConfigured
     */
    public function failsIfResourceIsNoUriAndNotInDirectory(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectDeprecationMessage('Resource not found in directory');

        $client = new AcmeClient(
            \getenv('PEBBLE_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            (new HttpClientBuilder)->usingPool($this->httpPool)->build()
        );
        $client->post('foobar', []);
    }

    /**
     * @test
     * @depends pebbleConfigured
     */
    public function canFetchDirectory(): void
    {
        $client = new AcmeClient(
            \getenv('PEBBLE_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            (new HttpClientBuilder)->usingPool($this->httpPool)->build()
        );

        $response = $client->get(\getenv('PEBBLE_HOST') . '/dir');
        $this->assertSame(200, $response->getStatus());

        $data = \json_decode($response->getBody()->buffer(), true);
        $this->assertIsArray($data);

        $acmeResources = (new ReflectionClass(AcmeResource::class))->getConstants();
        foreach ($acmeResources as $acmeResource) {
            // newAuthz is optional
            if ($acmeResource !== AcmeResource::NEW_AUTHORIZATION) {
                $this->assertArrayHasKey($acmeResource, $data);
            }
        }
    }

    /**
     * @test
     * @depends pebbleConfigured
     */
    public function fetchesNonceWhenNoneAvailable(): void
    {
        $client = new AcmeClient(
            \getenv('PEBBLE_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            (new HttpClientBuilder)->usingPool($this->httpPool)->build()
        );

        $client->post(\getenv('PEBBLE_HOST') . '/sign-me-up', []);
        $this->addToAssertionCount(1);
    }

    /**
     * @test
     * @depends pebbleConfigured
     */
    public function failsIfDnsFails(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessageMatches('~GET request to .* failed~');

        $resolver = $this->getMockBuilder(Resolver::class)->getMock();
        $resolver->method('resolve')->willThrowException(new NoRecordException);

        resolver($resolver);

        $client = new AcmeClient(
            \getenv('PEBBLE_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            (new HttpClientBuilder)->usingPool($this->httpPool)->build()
        );

        $client->get('https://localhost:4000/');
    }

    /**
     * @test
     * @depends pebbleConfigured
     */
    public function failsWithInvalidDirectoryResponse(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Invalid directory response. HTTP response code: 400');

        $interceptor = new class implements ApplicationInterceptor {
            public function request(
                Request $request,
                Cancellation $cancellation,
                DelegateHttpClient $httpClient
            ): Response {
                return new Response('1.1', 400, 'Bad request', [], new ReadableBuffer, $request);
            }
        };

        $httpClient = (new HttpClientBuilder)
            ->intercept($interceptor)
            ->usingPool($this->httpPool)
            ->build();

        $client = new AcmeClient(
            \getenv('PEBBLE_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            $httpClient
        );

        $client->get(AcmeResource::NEW_ACCOUNT);
    }

    /**
     * @test
     * @depends pebbleConfigured
     */
    public function failsWithInvalidDirectoryResponseButCorrectErrorResponse(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Could not obtain directory: Invalid directory response: Foobar');

        $interceptor = new class implements ApplicationInterceptor {
            public function request(
                Request $request,
                Cancellation $cancellation,
                DelegateHttpClient $httpClient
            ): Response {
                return new Response('1.1', 400, 'Bad request', [], new ReadableBuffer(\json_encode([
                    'type' => 'acme:error:foo',
                    'detail' => 'Foobar',
                ])), $request);
            }
        };

        $httpClient = (new HttpClientBuilder)
            ->intercept($interceptor)
            ->usingPool($this->httpPool)
            ->build();

        $client = new AcmeClient(
            \getenv('PEBBLE_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            $httpClient
        );

        $client->get(AcmeResource::NEW_ACCOUNT);
    }

    /**
     * @test
     * @depends pebbleConfigured
     */
    public function failsWithTooManyBadNonceErrors(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('too many errors (last code: 400)');

        $interceptor = new class implements ApplicationInterceptor {
            public function request(
                Request $request,
                Cancellation $cancellation,
                DelegateHttpClient $httpClient
            ): Response {
                if ($request->getMethod() === 'POST') {
                    return new Response('1.1', 400, 'Bad request', [], new ReadableBuffer(\json_encode([
                        'type' => 'acme:error:badNonce',
                    ])), $request);
                }

                return $httpClient->request($request, $cancellation);
            }
        };

        $httpClient = (new HttpClientBuilder)
            ->intercept($interceptor)
            ->usingPool($this->httpPool)
            ->build();

        $client = new AcmeClient(
            \getenv('PEBBLE_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            $httpClient
        );

        $client->post(AcmeResource::NEW_ACCOUNT, []);
    }

    /**
     * @test
     * @depends pebbleConfigured
     */
    public function succeedsWithOneBadNonceError(): void
    {
        $interceptor = new class implements ApplicationInterceptor {
            public $encounteredBadNonceError = false;

            public function request(
                Request $request,
                Cancellation $cancellation,
                DelegateHttpClient $httpClient
            ): Response {
                if (!$this->encounteredBadNonceError && $request->getMethod() === 'POST') {
                    $this->encounteredBadNonceError = true;

                    return new Response('1.1', 400, 'Bad request', [], new ReadableBuffer(\json_encode([
                        'type' => 'acme:error:badNonce',
                    ])), $request);
                }

                return $httpClient->request($request, $cancellation);
            }
        };

        $httpClient = (new HttpClientBuilder)
            ->intercept($interceptor)
            ->usingPool($this->httpPool)
            ->build();

        $client = new AcmeClient(
            \getenv('PEBBLE_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            $httpClient
        );

        $client->post(AcmeResource::NEW_ACCOUNT, []);

        $this->assertTrue($interceptor->encounteredBadNonceError);
    }
}
