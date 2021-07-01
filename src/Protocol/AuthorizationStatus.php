<?php

namespace Kelunik\Acme\Protocol;

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
 */
final class AuthorizationStatus
{
    public const PENDING = 'pending';
    public const VALID = 'valid';
    public const INVALID = 'invalid';
    public const DEACTIVATED = 'deactivated';
    public const EXPIRED = 'expired';
    public const REVOKED = 'revoked';

    public static function isKnown(string $status): bool
    {
        return \in_array($status, self::getAll(), true);
    }

    public static function getAll(): array
    {
        return [self::PENDING, self::VALID, self::INVALID, self::DEACTIVATED, self::EXPIRED, self::REVOKED];
    }

    private function __construct()
    {
        // disabled
    }
}
