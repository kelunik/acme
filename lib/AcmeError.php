<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
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