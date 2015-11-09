<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class AcmeError {
    const TYPE_BAD_CSR = "badCSR";
    const TYPE_BAD_NONCE = "badNonce";
    const TYPE_CONNECTION = "connection";
    const TYPE_DNSSEC = "dnssec";
    const TYPE_MALFORMED = "malformed";
    const TYPE_SERVER_INTERNAL = "serverInternal";
    const TYPE_TLS = "tls";
    const TYPE_UNAUTHORIZED = "unauthorized";
    const TYPE_UNKNOWN_HOST = "unknownHost";
}