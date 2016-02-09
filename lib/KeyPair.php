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

    /**
     * KeyPair constructor.
     *
     * @param string $private private key (PEM encoded)
     * @param string $public public key (PEM encoded)
     */
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

    /**
     * @api
     * @return string private key (PEM encoded)
     */
    public function getPrivate() {
        return $this->private;
    }

    /**
     * @api
     * @return string public key (PEM encoded)
     */
    public function getPublic() {
        return $this->public;
    }
}