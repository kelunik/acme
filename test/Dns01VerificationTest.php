<?php

namespace Kelunik\Acme;

use Amp\Artax\Response;

class Dns01VerificationTest extends \PHPUnit_Framework_TestCase {
    public function setUp() {
        \Amp\reactor(\Amp\driver());
    }

    /**
     * @test
     */
    public function failsOnDnsNotFound() {
        \Amp\run(function() {
            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client, $keyPair);

            /** @var Response $payloadResponse */
            $payload = "foobar";

            try {
            	yield $service->verifyDns01Challenge("google.com", $payload);
            } catch (AcmeException $e) {
            	$this->assertEquals($e->getMessage(), "Verification failed, no DNS record found for expected domain: _acme-challenge.google.com");
            } finally {
                \Amp\stop();
			}
        });
    }

    /**
     * @test
     */
    public function failsOnWrongPayload() {
    	\Amp\run(function() {
            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client, $keyPair);

            /** @var Response $payloadResponse */
            $payload = "foobar";

            try {
            	yield $service->verifyDns01Challenge("kevin-test.kf.porticor.net", $payload);
                $this->fail("Didn't throw expected exception.");
            } catch (AcmeException $e) {
            	$this->assertEquals($e->getMessage(), "Verification failed, please check DNS record under '_acme-challenge.kevin-test.kf.porticor.net'.");
            } finally {
				\Amp\stop();
			}
        });
    }
}