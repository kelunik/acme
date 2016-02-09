<?php

namespace Kelunik\Acme;

use Amp\Artax\Client;
use Amp\Artax\Response;

class SelfVerifyTest extends \PHPUnit_Framework_TestCase {
    /**
     * @test
     */
    public function ignoresWrongPeerName() {
        \Amp\run(function() {
            $http = new Client();

            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client, $keyPair);

            $token = "invalid-common-name";

            /** @var Response $payloadResponse */
            $payloadResponse = yield $http->request("http://blog.kelunik.com/robots.txt");
            $payload = trim($payloadResponse->getBody());

            try {
                yield $service->selfVerify("kelunik.com", $token, $payload);
                $this->assertTrue(true);
            } catch (\Throwable $e) {
                $this->fail("Didn't ignore invalid common name. " . $e);
            } catch (\Exception $e) {
                $this->fail("Didn't ignore invalid common name. " . $e);
            }

            \Amp\stop();
        });
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage selfVerify failed
     */
    public function failsOnDiffPayload() {
        \Amp\run(function() {
            $keyPair = (new OpenSSLKeyGenerator())->generate();
            $client = new AcmeClient("https://acme-staging.api.letsencrypt.org/directory", $keyPair);
            $service = new AcmeService($client, $keyPair);

            $token = "abcdef";

            /** @var Response $payloadResponse */
            $payload = "foobar";

            yield $service->selfVerify("kelunik.com", $token, $payload);

            \Amp\stop();
        });
    }
}
