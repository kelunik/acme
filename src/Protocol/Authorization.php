<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Protocol;

use Kelunik\Acme\AcmeException;
use League\Uri\Http;
use Psr\Http\Message\UriInterface;

final class Authorization
{
    public static function fromResponse(?string $url, string $payload): Authorization
    {
        if ($url === null) {
            throw new AcmeException('Missing authorization URL');
        }

        return new self(Http::createFromString($url), ...parseResponse($payload, [
            'identifier' => identifier(),
            'status' => enum(AuthorizationStatus::getAll()),
            'expires' => dateTime(),
            'challenges' => multiple(challenge()),
            'wildcard' => optional(boolean()),
        ]));
    }

    private UriInterface $url;

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

    private bool $wildcard;

    /**
     * Authorization constructor.
     *
     * @param string             $status The status of this account.
     * @param Challenge[]        $challenges
     */
    public function __construct(
        UriInterface  $url,
        Identifier $identifier,
        string $status,
        \DateTimeImmutable $expires,
        array $challenges = [],
        ?bool $wildcard = false
    ) {
        $this->url = $url;
        $this->identifier = $identifier;
        $this->status = $status;
        $this->expires = $expires;
        $this->challenges = $challenges;
        $this->wildcard = $wildcard ?? false;
    }

    public function getUrl(): UriInterface
    {
        return $this->url;
    }

    public function isWildcard(): bool
    {
        return $this->wildcard;
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
