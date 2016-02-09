<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class OpenSSLKeyGenerator implements KeyGenerator {
    /**
     * Generates a new key pair with the given length in bits.
     *
     * @api
     * @param int $bits length of the key
     * @return KeyPair generated key pair
     */
    public function generate($bits = 2048) {
        if (!is_int($bits)) {
            throw new \InvalidArgumentException(sprintf("\$bits must be of type int, %s given", gettype($bits)));
        }

        if ($bits < 2048) {
            throw new \InvalidArgumentException("Keys with fewer than 2048 bits are not allowed!");
        }

        $res = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => $bits,
        ]);

        $success = openssl_pkey_export($res, $privateKey);

        if (!$success) {
            throw new \RuntimeException("Key export failed!");
        }

        $publicKey = openssl_pkey_get_details($res)["key"];

        return new KeyPair($privateKey, $publicKey);
    }
}