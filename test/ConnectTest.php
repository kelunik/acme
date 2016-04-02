<?php

namespace Kelunik\Acme;

class ConnectTest extends \PHPUnit_Framework_TestCase {
    public function setUp() {
        \Amp\reactor(\Amp\driver());
		\Amp\Dns\resolver(\Amp\Dns\driver());
    }

	/**
	 * Test that TLS connections to the ACME server succeed.
	 * See https://github.com/amphp/socket/releases/tag/v0.9.6 for reasons.
	 *
	 * @test
     * @dataProvider provideCryptoConnectArgs
     */
    public function testCryptoConnect($uri, $options) {
        $promise = \Amp\Socket\cryptoConnect($uri, $options);
        $sock = \Amp\wait($promise);
        $this->assertTrue(is_resource($sock));
    }

    public function provideCryptoConnectArgs() {
        return [
            ['acme-v01.api.letsencrypt.org:443', []],
            ['acme-staging.api.letsencrypt.org:443', []],
        ];
    }
}
