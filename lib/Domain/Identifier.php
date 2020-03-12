<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Domain;

/**
 * ACME Identifier object.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class Identifier {
    /**
     * @var string Type validation of this identifier.
     */
    private $type;

    /**
     * @var string The identifier value.
     */
    private $value;

    /**
     * Identifier constructor.
     *
     * @param string $type
     * @param string $value
     */
    public function __construct(string $type, string $value) {
        $this->type = $type;
        $this->value = $value;
    }

    public static function fromResponse($payload): Identifier {
        return new Identifier($payload->type, $payload->value);
    }

    public function getType(): string {
        return $this->type;
    }

    public function getValue(): string {
        return $this->value;
    }
}
