<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Domain;

/**
 * ACME registration object.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class Registration extends AcmeResponse
{
    public static function fromResponse($payload): Registration
    {
        return new Registration(...self::parsePayloadWithProps($payload, [
            'location',
            'status',
            'contact' => [],
            'orders' => null,
        ]));
    }

    /**
     * @var string URI of the registration object.
     */
    private $location;

    /**
     * @var string The status of this account.
     */
    private $status;

    /**
     * @var array All contacts registered with the server.
     */
    private $contact;

    /**
     * @var null|string An url to fetch orders for this registration from
     */
    private $orders;

    /**
     * Registration constructor.
     *
     * @param string      $location URI of the registration object.
     * @param string      $status The status of this account.
     * @param array       $contact All contacts registered with the server.
     * @param string|null $orders An url to fetch orders for this registration from
     */
    public function __construct(string $location, string $status, array $contact = [], ?string $orders = null)
    {
        $this->location = $location;
        $this->status = $status;
        $this->contact = $contact;
        $this->orders = $orders;
    }

    /**
     * Gets the location URI.
     *
     * @return string URI to retrieve this registration object
     * @api
     */
    public function getLocation(): string
    {
        return $this->location;
    }

    /**
     * Gets the account status.
     *
     * @return string Status of this account.
     * @api
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * Gets the contact addresses.
     *
     * @return array Contacts registered with the server.
     * @api
     */
    public function getContact(): array
    {
        return $this->contact;
    }

    /**
     * Gets the order URI from which the orders of this account can be fetched.
     *
     * @return null|string URI to fetch orders from
     * @api
     */
    public function getOrders(): ?string
    {
        return $this->orders;
    }
}
