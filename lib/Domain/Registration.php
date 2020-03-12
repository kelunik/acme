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
class Registration {
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
     * @param string      $orders An url to fetch orders for this registration from
     */
    public function __construct(string $location, string $status, array $contact = [], string $orders = null) {
        $this->location = $location;
        $this->status = $status;
        $this->contact = $contact;
        $this->orders = $orders;
    }

    public static function fromResponse($payload): Registration {
        return new Registration($payload->location, $payload->status, $payload->contact, $payload->orders);
    }

    /**
     * Gets the location URI.
     *
     * @api
     * @return string URI to retrieve this registration object
     */
    public function getLocation(): string {
        return $this->location;
    }
    
    /**
     * Gets the account status.
     *
     * @api
     * @return string Status of this account.
     */
    public function getStatus() {
        return $this->status;
    }
    
    /**
     * Gets the contact addresses.
     *
     * @api
     * @return array Contacts registered with the server.
     */
    public function getContact(): array {
        return $this->contact;
    }

    /**
     * Gets the order URI from which the orders of this account can be fetched.
     *
     * @api
     * @return null|string URI to fetch orders from
     */
    public function getOrders() {
        return $this->orders;
    }
}
