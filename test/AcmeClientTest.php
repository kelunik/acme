<?php

namespace Kelunik\Acme;

class AcmeClientTest extends \PHPUnit_Framework_TestCase {
    protected function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());
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
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Could not obtain directory
     */
    public function failsIfDirectoryIsEmpty() {
        $client = new AcmeClient("http://127.0.0.1:4000/", (new OpenSSLKeyGenerator())->generate());
        \Amp\wait($client->get("foobar"));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage resource must be of type string
     */
    public function failsIfPostResourceIsEmpty() {
        $client = new AcmeClient("http://127.0.0.1:4000/directory", (new OpenSSLKeyGenerator())->generate());
        \Amp\wait($client->post(null, []));
    }
}