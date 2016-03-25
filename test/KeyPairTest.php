<?php

namespace Kelunik\Acme;

class KeyPairTest extends \PHPUnit_Framework_TestCase {
    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function privateNonString() {
        new KeyPair(false, "");
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function publicNonString() {
        new KeyPair("", false);
    }

    /**
     * @test
     */
    public function success() {
        $keyPair = new KeyPair("abc", "def");
        $this->assertSame("abc", $keyPair->getPrivate());
        $this->assertSame("def", $keyPair->getPublic());
    }
}
