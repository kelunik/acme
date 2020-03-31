<?php

namespace Kelunik\Acme;

use Kelunik\Acme\Domain\Authorization;
use Kelunik\Acme\Domain\Challenge;
use Kelunik\Acme\Domain\Identifier;
use Kelunik\Acme\Domain\Order;
use Kelunik\Acme\Domain\Registration;
use PHPUnit\Framework\TestCase;

class AcmeResponseTest extends TestCase {
    /**
     * @test
     */
    public function parseIdentifierObject() {
        $payloadIdentifier = new \stdClass();
        $payloadIdentifier->type = "type";
        $payloadIdentifier->value = "value";
        $identifier = Identifier::fromResponse($payloadIdentifier);

        $this->assertEquals("type", $identifier->getType());
        $this->assertEquals("value", $identifier->getValue());
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Error parsing property: value for Identifier response
     */
    public function failsParseIdentifierObject() {
        $payloadIdentifier = new \stdClass();
        $payloadIdentifier->type = "type";
        Identifier::fromResponse($payloadIdentifier);
    }

    /**
     * @test
     */
    public function parseChallengeObject() {
        $payloadChallenge = new \stdClass();
        $payloadChallenge->type = "type";
        $payloadChallenge->url = "url";
        $payloadChallenge->status = "status";
        $payloadChallenge->token = "token";
        $challenge = Challenge::fromResponse($payloadChallenge);

        $this->assertEquals("type", $challenge->getType());
        $this->assertEquals("url", $challenge->getUrl());
        $this->assertEquals("status", $challenge->getStatus());
        $this->assertEquals("token", $challenge->getToken());
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Error parsing property: token for Challenge response
     */
    public function failsParseChallengeObject() {
        $payloadChallenge = new \stdClass();
        $payloadChallenge->type = "type";
        $payloadChallenge->url = "url";
        $payloadChallenge->status = "status";
        Challenge::fromResponse($payloadChallenge);
    }

    /**
     * @test
     */
    public function parseAuthorizationObject() {
        $payloadChallenge = new \stdClass();
        $payloadChallenge->type = "type";
        $payloadChallenge->url = "url";
        $payloadChallenge->status = "status";
        $payloadChallenge->token = "token";

        $payloadIdentifier = new \stdClass();
        $payloadIdentifier->type = "type";
        $payloadIdentifier->value = "value";

        $payloadAuthorization = new \stdClass();
        $payloadAuthorization->identifier = $payloadIdentifier;
        $payloadAuthorization->status = "status";
        $payloadAuthorization->expires = "expires";
        $payloadAuthorization->challenges = [$payloadChallenge];

        $authorization = Authorization::fromResponse($payloadAuthorization);

        $this->assertEquals(Identifier::fromResponse($payloadIdentifier), $authorization->getIdentifier());
        $this->assertEquals("status", $authorization->getStatus());
        $this->assertEquals("expires", $authorization->getExpires());
        $this->assertEquals([Challenge::fromResponse($payloadChallenge)], $authorization->getChallenges());
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Error parsing property: identifier for Authorization response
     */
    public function failsParseIdentifierForAuthorizationObject() {
        $payloadChallenge = new \stdClass();
        $payloadChallenge->type = "type";
        $payloadChallenge->url = "url";
        $payloadChallenge->status = "status";
        $payloadChallenge->token = "token";

        $payloadAuthorization = new \stdClass();
        $payloadAuthorization->status = "status";
        $payloadAuthorization->expires = "expires";
        $payloadAuthorization->challenges = [$payloadChallenge];

        Authorization::fromResponse($payloadAuthorization);
    }

    /**
     * @test
     */
    public function parseChallengeForAuthorizationObject() {
        $payloadIdentifier = new \stdClass();
        $payloadIdentifier->type = "type";
        $payloadIdentifier->value = "value";

        $payloadAuthorization = new \stdClass();
        $payloadAuthorization->identifier = $payloadIdentifier;
        $payloadAuthorization->status = "status";
        $payloadAuthorization->expires = "expires";

        $authorization = Authorization::fromResponse($payloadAuthorization);

        $this->assertEquals(Identifier::fromResponse($payloadIdentifier), $authorization->getIdentifier());
        $this->assertEquals("status", $authorization->getStatus());
        $this->assertEquals("expires", $authorization->getExpires());
        $this->assertEquals([], $authorization->getChallenges());
    }

    /**
     * @test
     */
    public function parseOrderObjectWithDefaultValues() {
        $payloadIdentifier = new \stdClass();
        $payloadIdentifier->type = "type";
        $payloadIdentifier->value = "value";

        $payloadOrder = new \stdClass();
        $payloadOrder->location = "location";
        $payloadOrder->status = "status";
        $payloadOrder->identifiers = [$payloadIdentifier];
        $payloadOrder->authorizations = ["authorization1"];
        $payloadOrder->finalize = "finalize";

        $order = Order::fromResponse($payloadOrder);

        $this->assertEquals("location", $order->getLocation());
        $this->assertEquals("status", $order->getStatus());
        $this->assertEquals([Identifier::fromResponse($payloadIdentifier)], $order->getIdentifiers());
        $this->assertEquals(["authorization1"], $order->getAuthorizations());
        $this->assertEquals("finalize", $order->getFinalize());
        self::assertNull($order->getExpires());
        self::assertNull($order->getNotAfter());
        self::assertNull($order->getCertificate());
        self::assertNull($order->getNotBefore());
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Error parsing property: finalize for Order response
     */
    public function parseFailsOrderObject() {
        $payloadIdentifier = new \stdClass();
        $payloadIdentifier->type = "type";
        $payloadIdentifier->value = "value";

        $payloadOrder = new \stdClass();
        $payloadOrder->location = "location";
        $payloadOrder->status = "status";
        $payloadOrder->identifiers = [$payloadIdentifier];
        $payloadOrder->authorizations = ["authorization1"];

        Order::fromResponse($payloadOrder);
    }

    /**
     * @test
     */
    public function parseRegistrationObject() {
        $payloadRegistration = new \stdClass();
        $payloadRegistration->location = 'location';
        $payloadRegistration->status = 'status';
        $payloadRegistration->orders = "orders";

        $registration = Registration::fromResponse($payloadRegistration);
        $this->assertEquals("location", $registration->getLocation());
        $this->assertEquals("status", $registration->getStatus());
        $this->assertEquals("orders", $registration->getOrders());
        $this->assertEquals([], $registration->getContact());
    }

    /**
     * @test
     * @expectedException \Kelunik\Acme\AcmeException
     * @expectedExceptionMessage Error parsing property: status for Registration response
     */
    public function parseFailsRegistrationObject() {
        $payloadRegistration = new \stdClass();
        $payloadRegistration->location = 'location';

        Registration::fromResponse($payloadRegistration);
    }
}