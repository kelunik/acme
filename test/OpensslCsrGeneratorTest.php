<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\KeyGenerator;
use Kelunik\Acme\Crypto\PrivateKey;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use Kelunik\Acme\Csr\CsrGenerator;
use Kelunik\Acme\Csr\OpensslCsrGenerator;
use PHPUnit\Framework\TestCase;

class OpensslCsrGeneratorTest extends TestCase {
    /** @var KeyGenerator */
    private $keyGenerator;

    /** @var CsrGenerator */
    private $csrGenerator;

    public function setUp() {
        $this->keyGenerator = new RsaKeyGenerator;
        $this->csrGenerator = new OpensslCsrGenerator;
    }

    /**
     * @test
     * @expectedException \Error
     */
    public function failsWithInvalidConfig() {
        new OpensslCsrGenerator(['must_staple' => 'invalid']);
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     */
    public function failsWithInvalidKey() {
        \Amp\Promise\wait($this->csrGenerator->generateCsr(new PrivateKey('foo'), ['example.com']));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     */
    public function failsWithNoDomains() {
        \Amp\Promise\wait($this->csrGenerator->generateCsr($this->keyGenerator->generateKey(), []));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     */
    public function failsWithInvalidDomain() {
        \Amp\Promise\wait($this->csrGenerator->generateCsr($this->keyGenerator->generateKey(), ['foo,bar']));
    }

    /**
     * @test
     */
    public function succeedsOtherwise() {
        $csr = \Amp\Promise\wait($this->csrGenerator->generateCsr($this->keyGenerator->generateKey(), ['example.com']));
        $this->assertInternalType('string', $csr);
    }
}