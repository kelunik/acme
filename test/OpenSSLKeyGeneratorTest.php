<?php

namespace Kelunik\Acme;

class OpenSSLKeyGeneratorTest extends \PHPUnit_Framework_TestCase {
	private $generator;

	public function setUp() {
		$this->generator = new OpenSSLKeyGenerator;
	}

    /**
     * @test
	 * @expectedException \InvalidArgumentException
     */
    public function failsWithLessThan2048Bits() {
		$this->generator->generate(2047);
    }

	/**
     * @test
	 * @expectedException \InvalidArgumentException
     */
    public function failsWithNotInt() {
		$this->generator->generate("2048");
    }

	/**
	 * @test
	 */
	public function succeedsOtherwise() {
		$keyPair = $this->generator->generate();
		$this->assertInternalType("string", $keyPair->getPublic());
		$this->assertInternalType("string", $keyPair->getPrivate());
	}
}
