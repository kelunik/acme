<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\HttpClient;
use Amp\Artax\Request;
use Amp\Artax\Response;
use Amp\CoroutineResult;
use Amp\Dns\NoRecordException;
use Amp\Dns\Resolver;
use Amp\Failure;
use Amp\Success;

class AcmeClientTest extends \PHPUnit_Framework_TestCase {
    protected function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());
    }

    /**
     * @test
     */
    public function boulderConfigured() {
        if (getenv("BOULDER_HOST") === false) {
            $this->markTestSkipped("No Boulder host set. Set the environment variable BOULDER_HOST to enable those tests.");
        }

        $this->assertTrue(true);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage directoryUri must be of type string
     */
    public function failsIfDirectoryUriNotString() {
        new AcmeClient(null, (new OpenSSLKeyGenerator)->generate());
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Could not obtain directory
     */
    public function failsIfDirectoryIsEmpty() {
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/", (new OpenSSLKeyGenerator())->generate());
        \Amp\wait($client->get("foobar"));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage resource must be of type string
     */
    public function failsIfPostResourceIsEmpty() {
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate());
        \Amp\wait($client->post(null, []));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Resource not found in directory
     */
    public function failsIfResourceIsNoUriAndNotInDirectory() {
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate());
        \Amp\wait($client->post("foobar", []));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function canFetchDirectory() {
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate());

        /** @var Response $response */
        $response = \Amp\wait($client->get(getenv("BOULDER_HOST") . "/directory"));
        $this->assertSame(200, $response->getStatus());

        $data = json_decode($response->getBody(), true);

        $this->assertInternalType("array", $data);
        $this->assertArrayHasKey("new-authz", $data);
        $this->assertArrayHasKey("new-cert", $data);
        $this->assertArrayHasKey("new-reg", $data);
        $this->assertArrayHasKey("revoke-cert", $data);
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function fetchesNonceWhenNoneAvailable() {
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate());

        \Amp\wait($client->post(getenv("BOULDER_HOST") . "/acme/new-reg", []));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage HTTP response didn't carry replay-nonce header.
     */
    public function failsWithoutNonce() {
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate());

        \Amp\wait($client->post(getenv("BOULDER_HOST") . "/", []));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage could not obtain a replay nonce
     */
    public function failsIfHostNotAvailable() {
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate());

        // mute because of stream_socket_enable_crypto(): SSL: Connection refused warning
        @\Amp\wait($client->post("https://127.0.0.1:444/", []));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessageRegExp ~GET request to .* failed~
     */
    public function failsIfDnsFails() {
        $resolver = $this->getMockBuilder(Resolver::class)->getMock();
        $resolver->method("resolve")->willReturn(new Failure(new NoRecordException));

        \Amp\Dns\resolver($resolver);

        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate());

        \Amp\wait($client->get("https://localhost:4000/"));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage resource must be of type string
     */
    public function failsWithGetNotString() {
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate());

        \Amp\wait($client->get(null));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Invalid directory response. HTTP response code: 400
     */
    public function failsWithInvalidDirectoryResponse() {
        $http = $this->getMockBuilder(HttpClient::class)->getMock();
        $http->method("request")->willReturnCallback(function($request) {
            return \Amp\pipe((new Client)->request($request), function(Response $response) {
                return $response->setStatus(400);
            });
        });

        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate(), $http);

        \Amp\wait($client->get(AcmeResource::CHALLENGE));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Could not obtain directory: Invalid directory response: Foobar
     */
    public function failsWithInvalidDirectoryResponseButCorrectErrorResponse() {
        $http = $this->getMockBuilder(HttpClient::class)->getMock();
        $http->method("request")->willReturnCallback(function($request) {
            return \Amp\pipe((new Client)->request($request), function(Response $response) {
                return $response->setStatus(400)->setBody(json_encode([
                    "type" => "urn:acme:error:foo",
                    "detail" => "Foobar"
                ]));
            });
        });

        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate(), $http);

        \Amp\wait($client->get(AcmeResource::CHALLENGE));
    }

    /**
     * @test
     * @depends boulderConfigured
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage too many badNonce errors
     */
    public function failsWithTooManyBadNonceErrors() {
        $http = $this->getMockBuilder(HttpClient::class)->getMock();
        $http->method("request")->willReturnCallback(function($request) {
            return \Amp\pipe((new Client)->request($request), function(Response $response) {
                $request = $response->getRequest();

                if ($request instanceof Request && $request->getMethod() === "POST") {
                    $response->setStatus(400);
                    $response->setBody(json_encode([
                        "type" => "urn:acme:error:badNonce"
                    ]));
                }

                return $response;
            });
        });

        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate(), $http);

        \Amp\wait($client->post("new-reg", []));
    }

    /**
     * @test
     * @depends boulderConfigured
     */
    public function succeedsWithOneBadNonceError() {
        $encounteredBadNonceError = false;

        $http = $this->getMockBuilder(HttpClient::class)->getMock();
        $http->method("request")->willReturnCallback(function($request) use (&$encounteredBadNonceError) {
            return \Amp\pipe((new Client)->request($request), function(Response $response) use (&$encounteredBadNonceError) {
                $request = $response->getRequest();

                if (!$encounteredBadNonceError && $request instanceof Request && $request->getMethod() === "POST") {
                    $response->setStatus(400);
                    $response->setBody(json_encode([
                        "type" => "urn:acme:error:badNonce"
                    ]));

                    $encounteredBadNonceError = true;
                }

                return $response;
            });
        });

        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", (new OpenSSLKeyGenerator())->generate(), $http);

        \Amp\wait($client->post(AcmeResource::NEW_REGISTRATION, []));

        $this->assertTrue($encounteredBadNonceError);
    }
}
