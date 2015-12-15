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

    public function __construct($private, $public) {
        if (!is_string($private)) {
            throw new \InvalidArgumentException(sprintf("\$private must be of type string, %s given", gettype($private)));
        }

        if (!is_string($public)) {
            throw new \InvalidArgumentException(sprintf("\$public must be of type string, %s given", gettype($public)));
        }

        $this->private = $private;
        $this->public = $public;
    }

    public function getPrivate() {
        return $this->private;
    }

    public function getPublic() {
        return $this->public;
    }
}