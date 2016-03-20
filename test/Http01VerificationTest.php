<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\Response;

class Http01VerificationTest extends \PHPUnit_Framework_TestCase {
    public function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());
    }

    /**
     * @test
     */
    public function ignoresWrongPeerName() {
        \Amp\run(function () {
            $http = new Client();

            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client);

            $token = "invalid-common-name";

            /** @var Response $payloadResponse */
            $payloadResponse = (yield $http->request("http://blog.kelunik.com/robots.txt"));
            $payload = trim($payloadResponse->getBody());

            try {
                yield $service->verifyHttp01Challenge("kelunik.com", $token, $payload);
                $this->assertTrue(true);
            } catch (\Throwable $e) {
                $this->fail("Didn't ignore invalid common name. " . $e);
            } catch (\Exception $e) {
                $this->fail("Didn't ignore invalid common name. " . $e);
            } finally {
                \Amp\stop();
            }
        });
    }

    /**
     * @test
     */
    public function failsOnWrongPayload() {
        \Amp\run(function () {
            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client);

            $token = "abcdef";

            /** @var Response $payloadResponse */
            $payload = "foobar";

            try {
                yield $service->verifyHttp01Challenge("kelunik.com", $token, $payload);
                $this->assertTrue(true);
            } catch (AcmeException $e) {
                $this->assertContains("selfVerify failed", $e->getMessage());
            } finally {
                \Amp\stop();
            }
        });
    }
}
