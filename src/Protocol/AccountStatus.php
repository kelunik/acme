<?php

namespace Kelunik\Acme\Protocol;

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
 */
final class AccountStatus
{
    public const VALID = 'valid';
    public const DEACTIVATED = 'deactivated';
    public const REVOKED = 'revoked';

    public static function isKnown(string $status): bool
    {
        return \in_array($status, self::getAll(), true);
    }

    public static function getAll(): array
    {
        return [self::VALID, self::DEACTIVATED, self::REVOKED];
    }

    private function __construct()
    {
        // disabled
    }
}
