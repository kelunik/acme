<?php

namespace Kelunik\Acme\Protocol;

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
 */
final class OrderStatus
{
    public const INVALID = 'invalid';
    public const PENDING = 'pending';
    public const READY = 'ready';
    public const PROCESSING = 'processing';
    public const VALID = 'valid';

    public static function isKnown(string $status): bool
    {
        return \in_array($status, self::getAll(), true);
    }

    public static function getAll(): array
    {
        return [self::INVALID, self::PENDING, self::READY, self::PROCESSING, self::VALID];
    }

    private function __construct()
    {
        // disabled
    }
}
