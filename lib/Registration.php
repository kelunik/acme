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
    
    public function getContact() {
        return $this->contact;
    }
    
    public function getAgreement() {
        return $this->agreement;
    }
    
    public function getAuthorizations() {
        return $this->authorizations;
    }
    
    public function getCertificates() {
        return $this->certificates;
    }
}
