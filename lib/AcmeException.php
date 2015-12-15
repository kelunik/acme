<?php

namespace Kelunik\Acme;

use Exception;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class AcmeException extends Exception {
    public function __construct($message, $code = null, $previous = null) {
        parent::__construct($message, 0, $previous);
        $this->code = $code;
    }
}