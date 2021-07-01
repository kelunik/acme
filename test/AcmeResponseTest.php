<?php

namespace Kelunik\Acme;

use Assert\InvalidArgumentException;
use Kelunik\Acme\Protocol\Authorization;
use Kelunik\Acme\Protocol\Challenge;
use Kelunik\Acme\Protocol\Identifier;
use PHPUnit\Framework\TestCase;
use function Kelunik\Acme\Protocol\identifier;

class AcmeResponseTest extends TestCase
{
    /**
     * @test
     */
    public function parseIdentifierObject(): void
    {
        $identifier = identifier()(['value' => 'value', 'type' => 'type']);

        $this->assertSame("type", $identifier->getType());
        $this->assertSame("value", $identifier->getValue());
    }

    /**
     * @test
     */
    public function failsParseIdentifierObject(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Array does not contain an element with key "value"');

        identifier()(['type' => 'type']);
    }

    /**
     * @test
     */
    public function parseChallengeObject(): void
    {
        $challenge = Challenge::fromResponse('{ "type": "http-01", "url": "https://example.com/acme/chall/prV_B7yEyA4", "status": "valid", "validated": "2014-12-01T12:05:13.72Z", "token": "IlirfxKKXAsHtmzK29Pj8A" }');

        $this->assertEquals("http-01", $challenge->getType());
        $this->assertEquals("https://example.com/acme/chall/prV_B7yEyA4", (string) $challenge->getUrl());
        $this->assertEquals("valid", $challenge->getStatus());
        $this->assertEquals("IlirfxKKXAsHtmzK29Pj8A", $challenge->getToken());
    }

    /**
     * @test
     */
    public function failsParseChallengeObject(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Invalid response');

        Challenge::fromResponse('{ "type": "http-01", "url": "https://example.com/acme/chall/prV_B7yEyA4", "status": "foobar", "validated": "2014-12-01T12:05:13.72Z", "token": "IlirfxKKXAsHtmzK29Pj8A" }');
    }

    /**
     * @test
     */
    public function parseAuthorizationObject(): void
    {
        $authorization = Authorization::fromResponse('{
     "status": "valid",
     "expires": "2018-09-09T14:09:01.13Z",

     "identifier": {
       "type": "dns",
       "value": "www.example.org"
     },

     "challenges": [
       {
         "type": "http-01",
         "url": "https://example.com/acme/chall/prV_B7yEyA4",
         "status": "valid",
         "validated": "2014-12-01T12:05:13.72Z",
         "token": "IlirfxKKXAsHtmzK29Pj8A"
       }
     ]
   }');

        $this->assertEquals(new Identifier('dns', 'www.example.org'), $authorization->getIdentifier());
        $this->assertSame("valid", $authorization->getStatus());
        $this->assertSame('2018', $authorization->getExpires()->format('Y'));
        $this->assertCount(1, $authorization->getChallenges());
        $this->assertSame('http-01', $authorization->getChallenges()[0]->getType());
    }

    /**
     * @test
     */
    public function failsParseIdentifierForAuthorizationObject(): void
    {
        $this->expectException(AcmeException::class);
        $this->expectExceptionMessage('Invalid response');

        Authorization::fromResponse('{
     "status": "valid",
     "expires": "2018-09-09T14:09:01.13Z",

     "identifier": {
       "type": "dns",
       "value": "www.example.org"
     }
   }');
    }
}
