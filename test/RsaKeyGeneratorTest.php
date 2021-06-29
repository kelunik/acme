<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\KeyGenerator;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;

class RsaKeyGeneratorTest extends TestCase
{
    /** @var KeyGenerator */
    private $generator;

    public function setUp(): void
    {
        $this->generator = new RsaKeyGenerator;
    }

    /**
     * @test
     */
    public function failsWithLessThan2048Bits(): void
    {
        $this->expectException(\Error::class);

        new RsaKeyGenerator(2047);
    }

    /**
     * @test
     */
    public function succeedsOtherwise(): void
    {
        $key = $this->generator->generateKey();
        $this->assertIsString($key->toPem());
    }
}
