<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;

class AcmeServiceTest extends TestCase {
    /**
     * @var AcmeService
     */
    private $acme;

    public function setUp() {
        if (getenv('BOULDER_HOST') === false) {
            $this->markTestSkipped('No Boulder host set. Set the environment variable BOULDER_HOST to enable those tests.');
        }

        $key = (new RsaKeyGenerator)->generateKey();
        $client = new AcmeClient(getenv('BOULDER_HOST') . '/directory', $key);
        $this->acme = new AcmeService($client);
    }

    /**
     * @test
     */
    public function register() {
        /** @var Registration $registration */
        $registration = \Amp\Promise\wait($this->acme->register('me@example.com'));

        $this->assertSame(['mailto:me@example.com'], $registration->getContact());
        $this->assertNotNull($registration->getLocation());
    }
}
