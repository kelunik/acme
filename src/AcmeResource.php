<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

/**
 * Collection of ACME resources.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
final class AcmeResource
{
    /**
     * New order.
     */
    public const NEW_ORDER = 'newOrder';

    /**
     * New account.
     */
    public const NEW_ACCOUNT = 'newAccount';

    /**
     * New nonce.
     */
    public const NEW_NONCE = 'newNonce';

    /**
     * Revoke certificate.
     */
    public const REVOKE_CERTIFICATE = 'revokeCert';

    /**
     * Key change.
     */
    public const KEY_CHANGE = 'keyChange';


    public static function requiresJwkAuthorization(string $resource): bool
    {
        return $resource === self::NEW_ACCOUNT;
    }
}
