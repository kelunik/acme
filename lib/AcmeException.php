<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Exception;

/**
 * Generic ACME exception.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class AcmeException extends Exception {
    /**
     * AcmeException constructor.
     *
     * @param string      $message detailed error message
     * @param string|null $code ACME error code
     * @param null        $previous previous exception
     */
    public function __construct($message, $code = null, $previous = null) {
        parent::__construct($message, 0, $previous);
        $this->code = $code;
    }
}