<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class Registration {
    private $contact;

    public function __construct(array $contact) {
        $this->contact = $contact;
    }

    public function getContact() {
        return $this->contact;
    }
}