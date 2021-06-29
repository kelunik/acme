<?php

namespace Kelunik\Acme;

use Amp\ByteStream\InMemoryStream;
use Amp\CancellationToken;
use Amp\Dns\NoRecordException;
use Amp\Dns\Resolver;
use Amp\Failure;
use Amp\Http\Client\ApplicationInterceptor;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\Promise;
use Amp\Success;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use function Amp\Dns\resolver;

class AcmeClientTest extends TestCase
{
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
    public function failsIfPostResourceIsEmpty(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectDeprecationMessage('must be of the type string');

        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());
        Promise\wait($client->post(null, []));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsIfResourceIsNoUriAndNotInDirectory(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectDeprecationMessage('Resource not found in directory');

        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());
        Promise\wait($client->post('foobar', []));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function canFetchDirectory(): void
    {
        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        /** @var Response $response */
        $response = Promise\wait($client->get(\getenv('BOULDER_HOST') . '/directory'));
        $this->assertSame(200, $response->getStatus());

        $data = \json_decode(Promise\wait($response->getBody()->buffer()), true);
        $this->assertIsArray($data);

        $acmeResources = (new ReflectionClass(AcmeResource::class))->getConstants();
        foreach ($acmeResources as $acmeResource) {
            $this->assertArrayHasKey($acmeResource, $data);
        }
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function fetchesNonceWhenNoneAvailable(): void
    {
        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        Promise\wait($client->post(\getenv('BOULDER_HOST') . '/acme/new-acct', []));
        $this->addToAssertionCount(1);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsIfHostNotAvailable(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessageMatches('~POST request to .* failed~');

        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        // mute because of stream_socket_enable_crypto(): SSL: Connection refused warning
        @Promise\wait($client->post('https://127.0.0.1:444/', []));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsIfDnsFails(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessageMatches('~GET request to .* failed~');

        $resolver = $this->getMockBuilder(Resolver::class)->getMock();
        $resolver->method('resolve')->willReturn(new Failure(new NoRecordException));

        resolver($resolver);

        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        Promise\wait($client->get('https://localhost:4000/'));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsWithGetNotString(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectDeprecationMessage('must be of the type string');

        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        Promise\wait($client->get(null));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsWithInvalidDirectoryResponse(): void
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
            ->build();

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/directory',
            (new RsaKeyGenerator())->generateKey(),
            null,
            $httpClient
        );

        Promise\wait($client->get(AcmeResource::NEW_ACCOUNT));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsWithInvalidDirectoryResponseButCorrectErrorResponse(): void
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
            ->build();

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/directory',
            (new RsaKeyGenerator())->generateKey(),
            null,
            $httpClient
        );

        Promise\wait($client->get(AcmeResource::NEW_ACCOUNT));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function failsWithTooManyBadNonceErrors(): void
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
            ->build();

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/directory',
            (new RsaKeyGenerator())->generateKey(),
            null,
            $httpClient
        );

        Promise\wait($client->post(AcmeResource::NEW_ACCOUNT, []));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function succeedsWithOneBadNonceError(): void
    {
        $interceptor = new class implements ApplicationInterceptor {
            public $encounteredBadNonceError = false;

            public function request(
                Request $request,
                CancellationToken $cancellation,
                DelegateHttpClient $httpClient
            ): Promise {
                if (!$this->encounteredBadNonceError) {
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
            ->build();

        $client = new AcmeClient(
            \getenv('BOULDER_HOST') . '/directory',
            (new RsaKeyGenerator())->generateKey(),
            null,
            $httpClient
        );

        Promise\wait($client->post(AcmeResource::NEW_ACCOUNT, []));

        $this->assertTrue($interceptor->encounteredBadNonceError);
    }
}
