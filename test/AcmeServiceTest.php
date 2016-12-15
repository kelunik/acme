<?php

namespace Kelunik\Acme;

class AcmeServiceTest extends \PHPUnit_Framework_TestCase {
    /**
     * @var AcmeService
     */
    private $acme;

    public function setUp() {
        \Amp\reactor(\Amp\driver());
        \Amp\Dns\resolver(\Amp\Dns\driver());

        if (getenv("BOULDER_HOST") === false) {
            $this->markTestSkipped("No Boulder host set. Set the environment variable BOULDER_HOST to enable those tests.");
        }

        $keyPair = (new OpenSSLKeyGenerator())->generate();
        $client = new AcmeClient(getenv("BOULDER_HOST") . "/directory", $keyPair);
        $this->acme = new AcmeService($client);
    }

    /**
     * @test
     */
    public function register() {
        /** @var Registration $registration */
        $registration = \Amp\wait($this->acme->register("me@example.com"));

        $this->assertSame(["mailto:me@example.com"], $registration->getContact());
        $this->assertNotNull($registration->getLocation());
    }
}
