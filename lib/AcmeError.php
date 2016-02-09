<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

/**
 * Collection of ACME error codes.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class AcmeError {
    /**
     * Bad CSR.
     */
    const TYPE_BAD_CSR = "badCSR";

    /**
     * Bad replay nonce.
     */
    const TYPE_BAD_NONCE = "badNonce";

    /**
     * Connection error.
     */
    const TYPE_CONNECTION = "connection";

    /**
     * Error related to DNSSEC.
     */
    const TYPE_DNSSEC = "dnssec";

    /**
     * Malformed request.
     */
    const TYPE_MALFORMED = "malformed";

    /**
     * Internal server error.
     */
    const TYPE_SERVER_INTERNAL = "serverInternal";

    /**
     * TLS error.
     */
    const TYPE_TLS = "tls";

    /**
     * Unauthorized.
     */
    const TYPE_UNAUTHORIZED = "unauthorized";

    /**
     * Unknown host.
     */
    const TYPE_UNKNOWN_HOST = "unknownHost";
}