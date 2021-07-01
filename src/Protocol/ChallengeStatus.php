<?php

namespace Kelunik\Acme\Protocol;

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-8
 */
final class ChallengeStatus
{
    public const PENDING = 'pending';
    public const PROCESSING = 'processing';
    public const VALID = 'valid';
    public const INVALID = 'invalid';

    public static function isKnown(string $status): bool
    {
        return \in_array($status, self::getAll(), true);
    }

    public static function getAll(): array
    {
        return [self::PENDING, self::PROCESSING, self::VALID, self::INVALID];
    }

    private function __construct()
    {
        // disabled
    }
}
