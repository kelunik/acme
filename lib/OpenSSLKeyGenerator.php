<?php

namespace Kelunik\Acme;

class OpenSSLKeyGenerator implements KeyGenerator {
    public function generate(int $bits = 2048): KeyPair {
        if ($bits < 2048) {
            throw new \RuntimeException("Keys with fewer than 2048 bits are not allowed!");
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