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
     * New nonce.
     */
    public const NEW_NONCE = 'newNonce';

    /**
     * New account.
     */
    public const NEW_ACCOUNT = 'newAccount';

    /**
     * New order.
     */
    public const NEW_ORDER = 'newOrder';

    /**
     * New authorization.
     */
    public const NEW_AUTHORIZATION = 'newAuthz';

    /**
     * Revoke certificate.
     */
    public const REVOKE_CERTIFICATE = 'revokeCert';

    /**
     * Change key.
     */
    public const CHANGE_KEY = 'keyChange';

    public static function getAll(): array
    {
        return [
            self::NEW_NONCE,
            self::NEW_ACCOUNT,
            self::NEW_ORDER,
            self::NEW_AUTHORIZATION,
            self::REVOKE_CERTIFICATE,
            self::CHANGE_KEY,
        ];
    }
}
