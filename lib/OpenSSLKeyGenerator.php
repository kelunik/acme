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
     * @param int|string $bits length of the key or the Eliptic curve name
     * @param $key_type int type of the key
     * @return KeyPair generated key pair
     */
    public function generate($bits = 2048, $key_type = OPENSSL_KEYTYPE_RSA) {
      $key_options = [];
      switch ($key_type) {
        case OPENSSL_KEYTYPE_RSA:
          if (!is_int($bits)) {
            throw new \InvalidArgumentException(sprintf("\$bits must be of type int, %s given", gettype($bits)));
          }

          if ($bits < 2048) {
            throw new \InvalidArgumentException("Keys with fewer than 2048 bits are not allowed!");
          }

          $key_options["private_key_bits"] = $bits;

          break;

        case OPENSSL_KEYTYPE_EC:
          if (!function_exists('openssl_get_curve_names')) {
            throw new \InvalidArgumentException("Attempting to create a key on a system that does not support EC keys.");
          }
          $curves = openssl_get_curve_names();
          if (!in_array($bits, $curves)) {
            throw new \InvalidArgumentException("Curve not supported on this system.");
          }

          $key_options['curve_name'] = $bits;
          $key_options['private_key_bits'] = 2048;

          break;

        default:
          throw new \InvalidArgumentException("Unsupported key type.");
      }

        $configFile = $defaultConfigFile = __DIR__ . "/../res/openssl.cnf";

        if (class_exists("Phar") && !empty(Phar::running(true))) {
            $configContent = file_get_contents($configFile);

            $configFile = tempnam(sys_get_temp_dir(), "acme_openssl_");
            file_put_contents($configFile, $configContent);

            register_shutdown_function(function () use ($configFile) {
                @unlink($configFile);
            });
        }

        $res = openssl_pkey_new([
            "private_key_type" => $key_type,
            "config" => $configFile,
        ] + $key_options);

        $success = openssl_pkey_export($res, $privateKey, null, [
            "config" => $configFile,
        ]);

        if ($configFile !== $defaultConfigFile) {
            @unlink($configFile);
        }

        if (!$success) {
            openssl_pkey_free($res);
            throw new \RuntimeException("Key export failed!");
        }

        $publicKey = openssl_pkey_get_details($res)["key"];

        openssl_pkey_free($res);

        // clear error buffer, because of minimalistic openssl.cnf
        while (openssl_error_string() !== false);

        return new KeyPair($privateKey, $publicKey);
    }
}
