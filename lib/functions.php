<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Kelunik\Acme\Crypto\Backend\Backend;
use Kelunik\Acme\Crypto\PrivateKey;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;

/**
 * Generates the a key authorization, which must be provided in challenges, e.g. directly in HTTP-01
 * and further encoded for DNS-01.
 *
 * @api
 *
 * @param PrivateKey $accountKey Account key pair.
 * @param string     $token Challenge token.
 * @param Backend    $cryptoBackend Crypto backend.
 *
 * @return string Key authorization.
 * @see https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#key-authorizations
 */
function generateKeyAuthorization(PrivateKey $accountKey, string $token, Backend $cryptoBackend): string {
    static $encoder;

    if (!$encoder) {
        $encoder = new Base64UrlSafeEncoder;
    }

    $jwk = $cryptoBackend->toJwk($accountKey);
    \ksort($jwk);

    return $token . '.' . $encoder->encode(\hash('sha256', \json_encode($jwk), true));
}

/**
 * Encodes a key authorization for use in the DNS-01 challenge as TXT payload.
 *
 * @api
 *
 * @param string $keyAuthorization Key authorization generated using `generateKeyAuthorization()`.
 *
 * @return string Base64Url-encoded SHA256 digest of the `$keyAuthorization`.
 *
 * @see https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-7.5
 */
function generateDns01Payload(string $keyAuthorization): string {
    static $encoder;

    if (!$encoder) {
        $encoder = new Base64UrlSafeEncoder;
    }

    return $encoder->encode(\hash('sha256', $keyAuthorization, true));
}
