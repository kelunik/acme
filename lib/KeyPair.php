<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

/**
 * RSA key pair.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class KeyPair {
    /**
     * @var string private key (PEM encoded)
     */
    private $private;

    /**
     * @var string public key (PEM encoded)
     */
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
     * Gets the private key.
     *
     * @api
     * @return string private key (PEM encoded)
     */
    public function getPrivate() {
        return $this->private;
    }

    /**
     * Gets the public key.
     *
     * @api
     * @return string public key (PEM encoded)
     */
    public function getPublic() {
        return $this->public;
    }
}