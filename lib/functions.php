<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use InvalidArgumentException;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;

/**
 * Generates the a key authorization, which must be provided in challenges, e.g. directly in HTTP-01
 * and further encoded for DNS-01.
 *
 * @api
 * @param KeyPair $accountKeyPair account key pair
 * @param string  $token challenge token
 * @return string payload to be provided at /.well-known/acme-challenge/$token for HTTP-01 and _acme-challenge.example.com for DNS-01
 * @throws AcmeException If something went wrong.
 * @see https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#key-authorizations
 */
function generateKeyAuthorization(KeyPair $accountKeyPair, $token) {
    if (!is_string($token)) {
        throw new InvalidArgumentException(sprintf("\$token must be of type string, %s given.", gettype($token)));
    }

    if (!$privateKey = openssl_pkey_get_private($accountKeyPair->getPrivate())) {
        throw new AcmeException("Couldn't read private key.");
    }

    if (!$details = openssl_pkey_get_details($privateKey)) {
        throw new AcmeException("Couldn't get private key details.");
    }

    if ($details["type"] !== OPENSSL_KEYTYPE_RSA) {
        throw new AcmeException("Key type not supported, only RSA supported currently.");
    }

    $enc = new Base64UrlSafeEncoder;

    $payload = [
        "e" => $enc->encode($details["rsa"]["e"]),
        "kty" => "RSA",
        "n" => $enc->encode($details["rsa"]["n"]),
    ];

    return $token . "." . $enc->encode(hash("sha256", json_encode($payload), true));
}

/**
 * Encodes a key authorization for use in the DNS-01 challenge as TXT payload.
 *
 * @api
 * @param string $keyAuthorization key authorization generated using `generateKeyAuthorization`
 * @return string Base64Url-encoded SHA256 digest of the `$keyAuthorization`
 * @see https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-7.5
 */
function generateDns01Payload($keyAuthorization) {
    $encoder = new Base64UrlSafeEncoder;
    return $encoder->encode(hash("sha256", $keyAuthorization, true));
}
