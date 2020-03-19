<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\RsaKeyGenerator;
use Kelunik\Acme\Domain\Registration;
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
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage must agree to terms of service.
     */
    public function registerNotAgreeTOS() {
        /** @var Registration $registration */
        $registration = \Amp\Promise\wait($this->acme->register('me@example.com'));
        $this->assertSame(['mailto:me@example.com'], $registration->getContact());
        $this->assertNotNull($registration->getLocation());
    }

    /**
     * @test
     */
    public function registerAndReRegisterGivesSameLocation() {
        $registration = \Amp\Promise\wait($this->acme->register('me@example.com'));
        $this->assertSame(['mailto:me@example.com'], $registration->getContact());
        $this->assertNotNull($l1 = $registration->getLocation());

        $registration = \Amp\Promise\wait($this->acme->register('me@example.com'));
        $this->assertSame(['mailto:me@example.com'], $registration->getContact());
        $this->assertNotNull($l2 = $registration->getLocation());

        $this->assertSame($l1, $l2);
    }
}
