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

    public function __construct(string $location, array $contact, string $agreement = null, array $authorizations = [], array $certificates = []) {
        $this->location = $location;
        $this->contact = $contact;
        $this->agreement = $agreement;
        $this->authorizations = $authorizations;
        $this->certificates = $certificates;
    }

    public function getLocation() {
        return $this->location;
    }

    public function setLocation(string $val) {
        $this->location = $val;
    }

    public function getContact() {
        return $this->contact;
    }

    public function setContact(array $val) {
        $this->contact = $val;
    }

    public function getAgreement() {
        return $this->agreement;
    }

    public function setAgreement(string $val) {
        $this->agreement = $val;
    }

    public function getAuthorizations() {
        return $this->authorizations;
    }

    public function setAuthorizations(array $val) {
        $this->authorizations = $val;
    }

    public function getCertificates() {
        return $this->certificates;
    }

    public function setCertificates(array $val) {
        $this->certificates = $val;
    }
}
