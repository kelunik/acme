<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Protocol;

use Psr\Http\Message\UriInterface;

final class Challenge
{
    public static function fromResponse(string $payload): Challenge
    {
        return new Challenge(...parseResponse($payload, [
            'type' => string(),
            'url' => url(),
            'status' => enum(ChallengeStatus::getAll()),
            'validated' => optional(dateTime()),
            'error' => optional(problem()),
            'token' => optional(string()),
        ]));
    }

    /**
     * @var string Type validation of this challenge.
     */
    private string $type;

    /**
     * @var UriInterface Challenge URL.
     */
    private UriInterface $url;

    /**
     * @var string Challenge status.
     */
    private string $status;

    private ?\DateTimeImmutable $validated;

    private ?Problem $error;

    /**
     * @var string|null Challenge token.
     */
    private ?string $token;

    public function __construct(
        string $type,
        UriInterface $url,
        string $status,
        ?\DateTimeImmutable $validated,
        ?Problem $error,
        ?string $token
    ) {
        $this->type = $type;
        $this->url = $url;
        $this->status = $status;
        $this->validated = $validated;
        $this->error = $error;
        $this->token = $token;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getUrl(): UriInterface
    {
        return $this->url;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getValidated(): ?\DateTimeImmutable
    {
        return $this->validated;
    }

    public function getError(): ?Problem
    {
        return $this->error;
    }

    public function getToken(): ?string
    {
        return $this->token;
    }
}
