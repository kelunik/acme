<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\DefaultClient;
use Amp\Artax\Request;
use Amp\Artax\Response;
use Amp\ByteStream\InMemoryStream;
use Amp\ByteStream\Message;
use Amp\Dns\NoRecordException;
use Amp\Dns\Resolver;
use Amp\Failure;
use Amp\Promise;
use Amp\Success;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;
use function Amp\coroutine;

class AcmeClientTest extends TestCase {
    /**
     * @test
     */
    public function boulderConfigured() {
        if (getenv('BOULDER_HOST') === false) {
            $this->markTestSkipped('No Boulder host set. Set the environment variable BOULDER_HOST to enable those tests.');
        }

        $this->assertTrue(true);
    }

    /**
     * @test
     * @expectedException \TypeError
     * @expectedExceptionMessage must be of the type string
     */
    public function failsIfDirectoryUriNotString() {
        new AcmeClient(null, (new RsaKeyGenerator)->generateKey());
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Could not obtain directory
     */
    public function failsIfDirectoryIsEmpty() {
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/', (new RsaKeyGenerator())->generateKey());
        Promise\wait($client->get('foobar'));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \TypeError
     * @expectedExceptionMessage must be of the type string
     */
    public function failsIfPostResourceIsEmpty() {
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());
        Promise\wait($client->post(null, []));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Resource not found in directory
     */
    public function failsIfResourceIsNoUriAndNotInDirectory() {
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());
        Promise\wait($client->post('foobar', []));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function canFetchDirectory() {
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        /** @var Response $response */
        $response = Promise\wait($client->get(getenv('BOULDER_HOST') . '/directory'));
        $this->assertSame(200, $response->getStatus());

        $data = json_decode(yield $response->getBody(), true);

        $this->assertInternalType('array', $data);
        $this->assertArrayHasKey('new-authz', $data);
        $this->assertArrayHasKey('new-cert', $data);
        $this->assertArrayHasKey('new-reg', $data);
        $this->assertArrayHasKey('revoke-cert', $data);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function fetchesNonceWhenNoneAvailable() {
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        Promise\wait($client->post(getenv('BOULDER_HOST') . '/acme/new-reg', []));
        $this->addToAssertionCount(1);
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage HTTP response didn't carry replay-nonce header.
     */
    public function failsWithoutNonce() {
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        Promise\wait($client->post(getenv('BOULDER_HOST') . '/', []));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage could not obtain a replay nonce
     */
    public function failsIfHostNotAvailable() {
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        // mute because of stream_socket_enable_crypto(): SSL: Connection refused warning
        @Promise\wait($client->post('https://127.0.0.1:444/', []));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessageRegExp ~GET request to .* failed~
     */
    public function failsIfDnsFails() {
        $resolver = $this->getMockBuilder(Resolver::class)->getMock();
        $resolver->method('resolve')->willReturn(new Failure(new NoRecordException));

        \Amp\Dns\resolver($resolver);

        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        Promise\wait($client->get('https://localhost:4000/'));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \TypeError
     * @expectedExceptionMessage must be of the type string
     */
    public function failsWithGetNotString() {
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey());

        Promise\wait($client->get(null));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Invalid directory response. HTTP response code: 400
     */
    public function failsWithInvalidDirectoryResponse() {
        $response = $this->getMockBuilder(Response::class)->getMock();
        $response->method('getStatus')->willReturn(400);
        $response->method('getBody')->willReturn(new Message(new InMemoryStream('')));

        $http = $this->getMockBuilder(Client::class)->getMock();
        $http->method('request')->willReturn(new Success($response));

        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey(), $http);

        Promise\wait($client->get(AcmeResource::CHALLENGE));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Could not obtain directory: Invalid directory response: Foobar
     */
    public function failsWithInvalidDirectoryResponseButCorrectErrorResponse() {
        $response = $this->getMockBuilder(Response::class)->getMock();
        $response->method('getStatus')->willReturn(400);
        $response->method('getBody')->willReturn(new Message(new InMemoryStream(json_encode([
            'type' => 'urn:acme:error:foo',
            'detail' => 'Foobar',
        ]))));

        $http = $this->getMockBuilder(Client::class)->getMock();
        $http->method('request')->willReturn(new Success($response));

        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey(), $http);

        Promise\wait($client->get(AcmeResource::CHALLENGE));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage too many errors (last code: 400)
     */
    public function failsWithTooManyBadNonceErrors() {
        $mockResponse = $this->getMockBuilder(Response::class)->getMock();
        $mockResponse->method('getStatus')->willReturn(400);
        $mockResponse->method('getBody')->willReturn(new Message(new InMemoryStream(json_encode([
            'type' => 'urn:acme:error:badNonce',
        ]))));

        $http = $this->getMockBuilder(Client::class)->getMock();
        $http->method('request')->willReturnCallback(function ($request) use ($mockResponse) {
            if (!$request instanceof Request) {
                $request = new Request($request);
            }

            if ($request->getMethod() === 'POST') {
                return new Success($mockResponse);
            }

            return (new DefaultClient)->request($request);
        });

        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey(), $http);

        Promise\wait($client->post('new-reg', []));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function succeedsWithOneBadNonceError() {
        $encounteredBadNonceError = false;

        $mockResponse = $this->getMockBuilder(Response::class)->getMock();
        $mockResponse->method('getStatus')->willReturn(400);
        $mockResponse->method('getBody')->willReturn(new Message(new InMemoryStream(json_encode([
            'type' => 'urn:acme:error:badNonce',
        ]))));

        $http = $this->getMockBuilder(Client::class)->getMock();
        $http->method('request')->willReturnCallback(coroutine(function ($request) use ($http, $mockResponse, &$encounteredBadNonceError) {
            if (!$request instanceof Request) {
                $request = new Request($request);
            }

            if (!$encounteredBadNonceError && $request->getMethod() === 'POST') {
                $encounteredBadNonceError = true;

                return new Success($mockResponse);
            }

            return (new DefaultClient)->request($request);
        }));

        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', (new RsaKeyGenerator())->generateKey(), $http);

        Promise\wait($client->post(AcmeResource::NEW_REGISTRATION, []));

        $this->assertTrue($encounteredBadNonceError);
    }
}
