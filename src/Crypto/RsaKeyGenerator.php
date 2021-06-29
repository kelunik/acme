<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Crypto;

use Phar;

/**
 * RSA key generator using OpenSSL.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class RsaKeyGenerator implements KeyGenerator
{
    private $bits;

    /**
     * RsaKeyGenerator constructor.
     *
     * @param int $bits Bits of the key to generate.
     */
    public function __construct(int $bits = 2048)
    {
        if ($bits < 2048) {
            throw new \Error('Keys with fewer than 2048 bits are not allowed.');
        }

        $this->bits = $bits;
    }

    /** @inheritdoc */
    public function generateKey(): PrivateKey
    {
        $configFile = $defaultConfigFile = __DIR__ . '/../../res/openssl.cnf';

        if (\class_exists('Phar') && !empty(Phar::running())) {
            $configContent = \file_get_contents($configFile);

            $configFile = \tempnam(\sys_get_temp_dir(), 'acme_openssl_');
            \file_put_contents($configFile, $configContent);

            \register_shutdown_function(function () use ($configFile) {
                @\unlink($configFile);
            });
        }

        $res = \openssl_pkey_new([
            'private_key_type' => \OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $this->bits,
            'config' => $configFile,
        ]);

        $success = \openssl_pkey_export($res, $privateKey, null, [
            'config' => $configFile,
        ]);

        if ($configFile !== $defaultConfigFile) {
            @\unlink($configFile);
        }

        if (\PHP_VERSION_ID < 80000) {
            \openssl_pkey_free($res);
        } else {
            unset($res);
        }

        if (!$success) {
            throw new CryptoException('Key export failed!');
        }

        /** @noinspection PhpStatementHasEmptyBodyInspection */
        /** @noinspection LoopWhichDoesNotLoopInspection */
        /** @noinspection MissingOrEmptyGroupStatementInspection */
        while (\openssl_error_string() !== false) {
            // clear error buffer, because of minimalistic openssl.cnf
        }

        return new PrivateKey($privateKey);
    }
}
