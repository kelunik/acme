<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Domain;

/**
 * ACME registration object.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class Authorization {
    /**
     * @var Identifier The subjective identifier.
     */
    private $identifier;

    /**
     * @var string The status of this authorization.
     */
    private $status;

    /**
     * @var string Expiry date of this authorization.
     */
    private $expires;

    /**
     * @var Challenge[] Possible challenges for this authorization.
     */
    private $challenges;

    /**
     * Authorization constructor.
     *
     * @param Identifier $identifier
     * @param string $status The status of this account.
     * @param string $expires
     * @param Challenge[] $challenges
     */
    public function __construct(Identifier $identifier, string $status, string $expires, array $challenges = []) {
        $this->identifier = $identifier;
        $this->status = $status;
        $this->expires = $expires;
        $this->challenges = $challenges;
    }

    public static function fromResponse($payload): Authorization {
        $identifier = Identifier::fromResponse($payload->identifier);
        $challenges = [];
        foreach ($payload->challenges ?? [] as $challenge) {
            $challenges[] = Challenge::fromResponse($challenge);
        }
        return new Authorization($identifier, $payload->status, $payload->expires, $challenges);
    }

    public function getIdentifier(): Identifier {
        return $this->identifier;
    }

    public function getStatus(): string {
        return $this->status;
    }

    public function getExpires(): string {
        return $this->expires;
    }

    /**
     * @return Challenge[]
     */
    public function getChallenges(): array {
        return $this->challenges;
    }
}
