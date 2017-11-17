<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\KeyGenerator;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;

class RsaKeyGeneratorTest extends TestCase {
    /** @var KeyGenerator */
    private $generator;

    public function setUp() {
        $this->generator = new RsaKeyGenerator;
    }

    /**
     * @test
     * @expectedException \Error
     */
    public function failsWithLessThan2048Bits() {
        new RsaKeyGenerator(2047);
    }

    /**
     * @test
     */
    public function succeedsOtherwise() {
        $key = $this->generator->generateKey();
        $this->assertInternalType('string', $key->toPem());
    }
}
