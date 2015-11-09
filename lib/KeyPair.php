<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class KeyPair {
    private $private;
    private $public;

    public function __construct(string $private, string $public) {
        $this->private = $private;
        $this->public = $public;
    }

    public function getPrivate(): string {
        return $this->private;
    }

    public function getPublic(): string {
        return $this->public;
    }
}