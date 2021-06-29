<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Domain;

/**
 * ACME Challenge object.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class Challenge extends AcmeResponse {
    /**
     * @var string Type validation of this challenge.
     */
    private $type;

    /**
     * @var string Challenge URL.
     */
    private $url;

    /**
     * @var string Challenge status.
     */
    private $status;

    /**
     * @var string Challenge token.
     */
    private $token;

    /**
     * Authorization constructor.
     *
     * @param string $type
     * @param string $url
     * @param string $status The status of this account.
     * @param string $token
     */
    public function __construct(string $type, string $url, string $status, string $token) {
        $this->type = $type;
        $this->url = $url;
        $this->status = $status;
        $this->token = $token;
    }

    public static function fromResponse($payload): Challenge {
        return new Challenge(...self::parsePayloadWithProps($payload, [
            'type', 'url', 'status', 'token'
        ]));
    }

    public function getType(): string {
        return $this->type;
    }

    public function getUrl(): string {
        return $this->url;
    }

    public function getStatus(): string {
        return $this->status;
    }

    public function getToken(): string {
        return $this->token;
    }
}
