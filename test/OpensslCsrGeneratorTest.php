<?php

namespace Kelunik\Acme;

use Amp\PHPUnit\AsyncTestCase;
use Kelunik\Acme\Crypto\KeyGenerator;
use Kelunik\Acme\Crypto\PrivateKey;
use Kelunik\Acme\Crypto\RsaKeyGenerator;
use Kelunik\Acme\Csr\CsrGenerator;
use Kelunik\Acme\Csr\OpensslCsrGenerator;

class OpensslCsrGeneratorTest extends AsyncTestCase
{
    /** @var KeyGenerator */
    private $keyGenerator;

    /** @var CsrGenerator */
    private $csrGenerator;

    public function setUp(): void
    {
        parent::setUp();

        $this->keyGenerator = new RsaKeyGenerator;
        $this->csrGenerator = new OpensslCsrGenerator;
    }

    /**
     * @test
     */
    public function failsWithInvalidConfig(): void
    {
        $this->expectException(\Error::class);

        new OpensslCsrGenerator(['must_staple' => 'invalid']);
    }

    /**
     * @test
     */
    public function failsWithInvalidKey(): \Generator
    {
        $this->expectException(AcmeException::class);

        yield $this->csrGenerator->generateCsr(new PrivateKey('foo'), ['example.com']);
    }

    /**
     * @test
     */
    public function failsWithNoDomains(): \Generator
    {
        $this->expectException(AcmeException::class);

        yield $this->csrGenerator->generateCsr($this->keyGenerator->generateKey(), []);
    }

    /**
     * @test
     */
    public function failsWithInvalidDomain(): \Generator
    {
        $this->expectException(AcmeException::class);

        yield $this->csrGenerator->generateCsr($this->keyGenerator->generateKey(), ['foo,bar']);
    }

    /**
     * @test
     */
    public function succeedsOtherwise(): \Generator
    {
        $csr = yield $this->csrGenerator->generateCsr($this->keyGenerator->generateKey(), ['example.com']);
        $this->assertIsString($csr);
    }
}
