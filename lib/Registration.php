<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class Registration {
    private $contact;
    private $agreement;
    private $authorizations;
    private $certificates;

    public function __construct(array $contact, string $agreement, string $authorizations, string $certificates) {
        $this->contact = $contact;
        $this->agreement = $agreement;
        $this->authorizations = $authorizations;
        $this->certificates = $certificates;
    }

    public function getContact(): array {
        return $this->contact;
    }

    public function getAgreement(): string {
        return $this->agreement;
    }

    public function getAuthorizations(): string {
        return $this->authorizations;
    }

    public function getCertificates(): string {
        return $this->certificates;
    }
}