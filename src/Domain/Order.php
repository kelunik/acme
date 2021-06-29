<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Domain;

use Kelunik\Acme\AcmeException;

/**
 * ACME Order object.
 *
 * @package Kelunik\Acme
 */
class Order extends AcmeResponse
{
    public static function fromResponse($payload): Order
    {
        $identifiers = [];
        foreach (self::getPropertyValue($payload, 'identifiers', false) ?? [] as $identifier) {
            $identifiers[] = Identifier::fromResponse($identifier);
        }
        $payload->identifiers = $identifiers;

        return new Order(...self::parsePayloadWithProps($payload, [
            'location',
            'status',
            'identifiers',
            'authorizations',
            'finalize',
            'expires' => null,
            'certificate' => null,
            'notBefore' => null,
            'notAfter' => null,
        ]));
    }
    /**
     * @var string The location URL of this order.
     */
    private $location;

    /**
     * @var string The status of this order.
     */
    private $status;

    /**
     * @var null|string Expiry date of this order. Required when $status is "valid" or "pending"
     * Format: "2016-01-01T00:00:00Z"
     */
    private $expires;

    /**
     * @var Identifier[] All identifiers corresponding this order.
     */
    private $identifiers;

    /**
     * @var string[] Authorizations each of the identifiers must met before certificate can be issued
     */
    private $authorizations;

    /**
     * @var string Finalize url to complete order once authorizations are met
     */
    private $finalize;

    /**
     * @var null|string The certificate URL that has been issued once this order is completed.
     */
    private $certificate;

    /**
     * @var null|string
     * Format: "2016-01-01T00:00:00Z"
     */
    private $notBefore;

    /**
     * @var null|string
     * Format: "2016-01-01T00:00:00Z"
     */
    private $notAfter;

    /**
     * Order constructor.
     *
     * @param string       $location
     * @param string       $status The status of this account.
     * @param Identifier[] $identifiers
     * @param string[]     $authorizations
     * @param string       $finalize
     * @param string|null  $expires
     * @param string|null  $certificate
     * @param string|null  $notBefore
     * @param string|null  $notAfter
     *
     * @throws AcmeException
     */
    public function __construct(
        string $location,
        string $status,
        array $identifiers,
        array $authorizations,
        string $finalize,
        string $expires = null,
        string $certificate = null,
        string $notBefore = null,
        string $notAfter = null
    ) {
        $this->location = $location;
        $this->status = $status;
        $this->identifiers = $identifiers;
        $this->authorizations = $authorizations;
        $this->finalize = $finalize;

        $this->expires = $expires;
        if (empty($expires) && \in_array($status, [OrderStatus::PENDING, OrderStatus::VALID], true)) {
            throw new AcmeException("Expires field is mandatory when order status is `pending` or `valid`");
        }

        $this->certificate = $certificate;
        $this->notBefore = $notBefore;
        $this->notAfter = $notAfter;
    }

    public function getLocation(): string
    {
        return $this->location;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * @return Identifier[]
     */
    public function getIdentifiers(): array
    {
        return $this->identifiers;
    }

    /**
     * @return string[]
     */
    public function getAuthorizations(): array
    {
        return $this->authorizations;
    }

    public function getFinalize(): string
    {
        return $this->finalize;
    }

    public function getExpires(): ?string
    {
        return $this->expires;
    }

    public function getCertificate(): ?string
    {
        return $this->certificate;
    }

    public function getNotBefore(): ?string
    {
        return $this->notBefore;
    }

    public function getNotAfter(): ?string
    {
        return $this->notAfter;
    }
}
