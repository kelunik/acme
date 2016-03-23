<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;
use Phar;

/**
 * RSA key generator using OpenSSL.
 *
 * @author Niklas Keller <me@kelunik.com>
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

        $configFile = __DIR__ . "/../res/openssl.cnf";

        if (class_exists("Phar") && !empty(Phar::running(true))) {
            $configContent = file_get_contents($configFile);
            $configFile = tempnam(sys_get_temp_dir(), "acme_openssl_");
            file_put_contents($configFile, $configContent);
        }

        $res = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => $bits,
            "config" => $configFile,
        ]);

        $success = openssl_pkey_export($res, $privateKey, null, [
            "config" => $configFile,
        ]);

        if (!$success) {
            throw new \RuntimeException("Key export failed!");
        }

        $publicKey = openssl_pkey_get_details($res)["key"];

        // clear error buffer, because of minimalistic openssl.cnf
        while (openssl_error_string() !== false);

        return new KeyPair($privateKey, $publicKey);
    }
}
