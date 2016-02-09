<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

/**
 * ACME registration object.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class Registration {
    /**
     * @var string URI of the registration object
     */
    private $location;

    /**
     * @var array all contacts registered with the server
     */
    private $contact;

    /**
     * @var null|string URI to the agreement, if agreed
     */
    private $agreement;

    /**
     * @var null|string URI to retrieve authorizations if provided
     */
    private $authorizations;

    /**
     * @var null|string URI to retrieve certificates if provided
     */
    private $certificates;

    /**
     * Registration constructor.
     *
     * @param string      $location URI of the registration object
     * @param array       $contact all contacts registered with the server
     * @param string|null $agreement URI to the agreement, if agreed
     * @param string      $authorizations URI to retrieve authorizations
     * @param string      $certificates URI to retrieve certificates
     */
    public function __construct($location, array $contact = [], $agreement = null, $authorizations = null, $certificates = null) {
        $this->location = $location;
        $this->contact = $contact;
        $this->agreement = $agreement;
        $this->authorizations = $authorizations;
        $this->certificates = $certificates;
    }

    /**
     * Gets the location URI.
     *
     * @api
     * @return string URI to retrieve this registration object
     */
    public function getLocation() {
        return $this->location;
    }

    /**
     * Gets the contact addresses.
     *
     * @api
     * @return array contacts registered with the server
     */
    public function getContact() {
        return $this->contact;
    }

    /**
     * Gets the agreement URI.
     *
     * @api
     * @return null|string URI to the agreement, if agreed, otherwise <code>null</code>
     */
    public function getAgreement() {
        return $this->agreement;
    }

    /**
     * Gets the authorizations URI.
     *
     * @api
     * @return null|string URI to retrieve authorizations or null
     */
    public function getAuthorizations() {
        return $this->authorizations;
    }

    /**
     * Gets the certificates URI.
     *
     * @api
     * @return null|string URI to retrieve certficates or null
     */
    public function getCertificates() {
        return $this->certificates;
    }
}
