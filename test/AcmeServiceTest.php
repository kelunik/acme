<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\RsaKeyGenerator;
use Kelunik\Acme\Domain\Registration;
use PHPUnit\Framework\TestCase;
use function Amp\Promise\wait;

class AcmeServiceTest extends TestCase
{
    /**
     * @var AcmeService
     */
    private $acme;

    public function setUp(): void
    {
        if (\getenv('BOULDER_HOST') === false) {
            $this->markTestSkipped('No Boulder host set. Set the environment variable BOULDER_HOST to enable those tests.');
        }

        $key = (new RsaKeyGenerator)->generateKey();
        $client = new AcmeClient(\getenv('BOULDER_HOST') . '/directory', $key);
        $this->acme = new AcmeService($client);
    }

    /**
     * @test
     */
    public function registerNotAgreeTOS(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('must agree to terms of service');

        /** @var Registration $registration */
        wait($this->acme->register('me@example.com'));
    }

    /**
     * @test
     */
    public function registerAndReRegisterGivesSameLocation(): void
    {
        $registration = wait($this->acme->register('me@example.com'));
        $this->assertSame(['mailto:me@example.com'], $registration->getContact());
        $this->assertNotNull($l1 = $registration->getLocation());

        $registration = wait($this->acme->register('me@example.com'));
        $this->assertSame(['mailto:me@example.com'], $registration->getContact());
        $this->assertNotNull($l2 = $registration->getLocation());

        $this->assertSame($l1, $l2);
    }
}
