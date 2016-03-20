<?php

namespace Kelunik\Acme;

use Amp\Artax\Response;
use Amp\Dns\NoRecordException;
use Amp\Dns\Record;
use Amp\Dns\Resolver;
use Amp\Failure;
use Amp\Success;
use RuntimeException;

class Dns01VerificationTest extends \PHPUnit_Framework_TestCase {
    public function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());
    }

    /**
     * @test
     */
    public function failsOnDnsNotFound() {
        \Amp\Dns\resolver(new NotFoundResolver);

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
        \Amp\Dns\resolver(new TxtResolver("xyz"));

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
        \Amp\Dns\resolver(new TxtResolver("foobar"));

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

class NotFoundResolver implements Resolver {
    public function resolve($name, array $options = []) {
        throw new RuntimeException("Not Implemented!");
    }

    public function query($name, $type, array $options = []) {
        return new Failure(new NoRecordException());
    }
}

class TxtResolver implements Resolver {
    private $payload;

    public function __construct($payload) {
        $this->payload = $payload;
    }

    public function resolve($name, array $options = []) {
        throw new RuntimeException("Not Implemented!");
    }

    public function query($name, $type, array $options = []) {
        return new Success([$this->payload, Record::TXT, 300]);
    }
}