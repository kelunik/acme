<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Protocol;

final class Authorization
{
    public static function fromResponse(string $payload): Authorization
    {
        return new self(...parseResponse($payload, [
            'identifier' => identifier(),
            'status' => enum(AuthorizationStatus::getAll()),
            'expires' => dateTime(),
            'challenges' => multiple(challenge()),
            'wildcard' => optional(boolean()),
        ]));
    }

    /**
     * @var Identifier The subjective identifier.
     */
    private Identifier $identifier;

    /**
     * @var string The status of this authorization.
     */
    private string $status;

    /**
     * @var \DateTimeImmutable Expiry date of this authorization.
     */
    private \DateTimeImmutable $expires;

    /**
     * @var Challenge[] Possible challenges for this authorization.
     */
    private array $challenges;

    /**
     * Authorization constructor.
     *
     * @param Identifier         $identifier
     * @param string             $status The status of this account.
     * @param \DateTimeImmutable $expires
     * @param Challenge[]        $challenges
     */
    public function __construct(
        Identifier $identifier,
        string $status,
        \DateTimeImmutable $expires,
        array $challenges = []
    ) {
        $this->identifier = $identifier;
        $this->status = $status;
        $this->expires = $expires;
        $this->challenges = $challenges;
    }

    public function getIdentifier(): Identifier
    {
        return $this->identifier;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getExpires(): \DateTimeImmutable
    {
        return $this->expires;
    }

    /**
     * @return Challenge[]
     */
    public function getChallenges(): array
    {
        return $this->challenges;
    }
}
