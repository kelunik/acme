<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class Registration {
    private $location;
    private $contact;
    private $agreement;
    private $authorizations;
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
     * @api
     * @return string URI to retrieve this registration object
     */
    public function getLocation() {
        return $this->location;
    }

    /**
     * @api
     * @return array contacts registered with the server
     */
    public function getContact() {
        return $this->contact;
    }

    /**
     * @api
     * @return null|string URI to the agreement, if agreed, otherwise <code>null</code>
     */
    public function getAgreement() {
        return $this->agreement;
    }

    /**
     * @api
     * @return null|string URI to retrieve authorizations or null
     */
    public function getAuthorizations() {
        return $this->authorizations;
    }

    /**
     * @api
     * @return null|string URI to retrieve certficates or null
     */
    public function getCertificates() {
        return $this->certificates;
    }
}
