<?php

namespace Kelunik\Acme;

use Kelunik\Acme\CSR\OpenSSLCSRGenerator;

class OpenSSLCSRGeneratorTest extends \PHPUnit_Framework_TestCase {
    /**
     * @var OpenSSLKeyGenerator
     */
    private $keyGenerator;

    /**
     * @var OpenSSLCSRGenerator
     */
    private $csrGenerator;

    public function setUp() {
        $this->csrGenerator = new OpenSSLCSRGenerator();
        $this->keyGenerator = new OpenSSLKeyGenerator();
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function failsWithInvalidConfig()
    {
        new OpenSSLCSRGenerator(["must_staple" => "invalid"]);
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     */
    public function failsWithInvalidKey()
    {
        \Amp\wait($this->csrGenerator->generate(new KeyPair("foo", "bar"), ["example.com"]));
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     */
    public function failsWithNoDomains()
    {
        \Amp\wait($this->csrGenerator->generate($this->keyGenerator->generate(), []));
    }

    /**
     * @test
     */
    public function succeedsOtherwise()
    {
        $csr = \Amp\wait($this->csrGenerator->generate($this->keyGenerator->generate(), ["example.com"]));

        $this->assertInternalType("string", $csr);
    }
}