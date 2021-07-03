<?php

namespace Kelunik\Acme;

use Amp\ByteStream\InMemoryStream;
use Amp\CancellationToken;
use Amp\Dns\NoRecordException;
use Amp\Dns\Resolver;
use Amp\Failure;
use Amp\Http\Client\ApplicationInterceptor;
use Amp\Http\Client\Connection\DefaultConnectionFactory;
use Amp\Http\Client\Connection\UnlimitedConnectionPool;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\PHPUnit\AsyncTestCase;
use Amp\Promise;
use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use Amp\Success;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use ReflectionClass;
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

    /**
     * @test
     */
    public function boulderConfigured(): void
    {
        if (\getenv('BOULDER_HOST') === false) {
            $this->markTestSkipped('No Boulder host set. Set the environment variable BOULDER_HOST to enable those tests.');
        }

        $this->assertTrue(true);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsIfResourceIsNoUriAndNotInDirectory(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectDeprecationMessage('Resource not found in directory');

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            (new HttpClientBuilder)->usingPool($this->httpPool)->build()
        );
        yield $client->post('foobar', []);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function canFetchDirectory(): \Generator
    {
        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            (new HttpClientBuilder)->usingPool($this->httpPool)->build()
        );

        /** @var Response $response */
        $response = yield $client->get(\getenv('BOULDER_HOST') . '/dir');
        $this->assertSame(200, $response->getStatus());

        $data = \json_decode(yield $response->getBody()->buffer(), true);
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
     * @depends boulderConfigured
     */
    public function fetchesNonceWhenNoneAvailable(): \Generator
    {
        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            (new HttpClientBuilder)->usingPool($this->httpPool)->build()
        );

        yield $client->post(\getenv('BOULDER_HOST') . '/sign-me-up', []);
        $this->addToAssertionCount(1);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsIfDnsFails(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessageMatches('~GET request to .* failed~');

        $resolver = $this->getMockBuilder(Resolver::class)->getMock();
        $resolver->method('resolve')->willReturn(new Failure(new NoRecordException));

        resolver($resolver);

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            (new HttpClientBuilder)->usingPool($this->httpPool)->build()
        );

        yield $client->get('https://localhost:4000/');
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsWithInvalidDirectoryResponse(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Invalid directory response. HTTP response code: 400');

        $interceptor = new class implements ApplicationInterceptor {
            public function request(
                Request $request,
                CancellationToken $cancellation,
                DelegateHttpClient $httpClient
            ): Promise {
                return new Success(new Response('1.1', 400, 'Bad request', [], new InMemoryStream, $request));
            }
        };

        $httpClient = (new HttpClientBuilder)
            ->intercept($interceptor)
            ->usingPool($this->httpPool)
            ->build();

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            $httpClient
        );

        yield $client->get(AcmeResource::NEW_ACCOUNT);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsWithInvalidDirectoryResponseButCorrectErrorResponse(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Could not obtain directory: Invalid directory response: Foobar');

        $interceptor = new class implements ApplicationInterceptor {
            public function request(
                Request $request,
                CancellationToken $cancellation,
                DelegateHttpClient $httpClient
            ): Promise {
                return new Success(new Response('1.1', 400, 'Bad request', [], new InMemoryStream(\json_encode([
                    'type' => 'acme:error:foo',
                    'detail' => 'Foobar',
                ])), $request));
            }
        };

        $httpClient = (new HttpClientBuilder)
            ->intercept($interceptor)
            ->usingPool($this->httpPool)
            ->build();

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            $httpClient
        );

        yield $client->get(AcmeResource::NEW_ACCOUNT);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsWithTooManyBadNonceErrors(): \Generator
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('too many errors (last code: 400)');

        $interceptor = new class implements ApplicationInterceptor {
            public function request(
                Request $request,
                CancellationToken $cancellation,
                DelegateHttpClient $httpClient
            ): Promise {
                if ($request->getMethod() === 'POST') {
                    return new Success(new Response('1.1', 400, 'Bad request', [], new InMemoryStream(\json_encode([
                        'type' => 'acme:error:badNonce',
                    ])), $request));
                }

                return $httpClient->request($request, $cancellation);
            }
        };

        $httpClient = (new HttpClientBuilder)
            ->intercept($interceptor)
            ->usingPool($this->httpPool)
            ->build();

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            $httpClient
        );

        yield $client->post(AcmeResource::NEW_ACCOUNT, []);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function succeedsWithOneBadNonceError(): \Generator
    {
        $interceptor = new class implements ApplicationInterceptor {
            public $encounteredBadNonceError = false;

            public function request(
                Request $request,
                CancellationToken $cancellation,
                DelegateHttpClient $httpClient
            ): Promise {
                if (!$this->encounteredBadNonceError && $request->getMethod() === 'POST') {
                    $this->encounteredBadNonceError = true;

                    return new Success(new Response('1.1', 400, 'Bad request', [], new InMemoryStream(\json_encode([
                        'type' => 'acme:error:badNonce',
                    ])), $request));
                }

                return $httpClient->request($request, $cancellation);
            }
        };

        $httpClient = (new HttpClientBuilder)
            ->intercept($interceptor)
            ->usingPool($this->httpPool)
            ->build();

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/dir',
            (new RsaKeyGenerator())->generateKey(),
            $httpClient
        );

        yield $client->post(AcmeResource::NEW_ACCOUNT, []);

        $this->assertTrue($interceptor->encounteredBadNonceError);
    }
}
