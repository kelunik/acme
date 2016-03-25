<?php

namespace Kelunik\Acme;

use Amp\Artax\Response;
use Amp\Dns\NoRecordException;
use Amp\Dns\Record;
use Amp\Dns\Resolver;
use Amp\Failure;
use Amp\Success;

class Dns01VerificationTest extends \PHPUnit_Framework_TestCase {
    public function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());
    }

    /**
     * @test
     */
    public function failsOnDnsNotFound() {
        $stub = $this->getMockBuilder(Resolver::class)->getMock();
        $stub->method("query")->willReturn(new Failure(new NoRecordException));
        \Amp\Dns\resolver($stub);

        \Amp\run(function () {
            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client);

            /** @var Response $payloadResponse */
            $payload = "foobar";

            try {
                yield $service->verifyDns01Challenge("example.com", $payload);
            } catch (AcmeException $e) {
                $this->assertEquals($e->getMessage(), "Verification failed, no DNS record found for expected domain: _acme-challenge.example.com");
            } finally {
                \Amp\stop();
            }
        });
    }

    /**
     * @test
     */
    public function failsOnWrongPayload() {
        $stub = $this->getMockBuilder(Resolver::class)->getMock();
        $stub->method("query")->willReturn(new Success(["xyz", Record::TXT, 300]));
        \Amp\Dns\resolver($stub);

        \Amp\run(function () {
            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client);

            /** @var Response $payloadResponse */
            $payload = "foobar";

            try {
                yield $service->verifyDns01Challenge("example.com", $payload);
                $this->fail("Didn't throw expected exception.");
            } catch (AcmeException $e) {
                $this->assertEquals($e->getMessage(), "Verification failed, please check DNS record under '_acme-challenge.example.com'.");
            } finally {
                \Amp\stop();
            }
        });
    }

    /**
     * @test
     */
    public function succeedsOnRightPayload() {
        $stub = $this->getMockBuilder(Resolver::class)->getMock();
        $stub->method("query")->willReturn(new Success(["foobar", Record::TXT, 300]));
        \Amp\Dns\resolver($stub);

        \Amp\run(function () {
            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client);

            /** @var Response $payloadResponse */
            $payload = "foobar";

            try {
                yield $service->verifyDns01Challenge("example.com", $payload);
                $this->assertTrue(true);
            } catch (\Throwable $e) {
                $this->fail("Didn't succeed: " . $e);
            } catch (\Exception $e) {
                $this->fail("Didn't succeed: " . $e);
            } finally {
                \Amp\stop();
            }
        });
    }
}