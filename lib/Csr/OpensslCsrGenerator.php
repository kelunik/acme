<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Csr;

use Amp\File;
use Amp\Promise;
use Amp\Uri\InvalidDnsNameException;
use Kelunik\Acme\AcmeException;
use Kelunik\Acme\Crypto\CryptoException;
use Kelunik\Acme\Crypto\PrivateKey;
use function Amp\call;
use function Amp\Uri\normalizeDnsName;

/**
 * Allows generating certificate signing requests using OpenSSL.
 *
 * @package Kelunik\Acme
 */
final class OpensslCsrGenerator implements CsrGenerator {
    private $mustStaple;

    /**
     * OpenSSLCSRGenerator constructor.
     *
     * @param array $options CSR options, currently only `'must_staple' => bool` is supported.
     *
     * @throws \TypeError If `'must_staple'` is not of type `bool`.
     */
    public function __construct(array $options = []) {
        $mustStaple = $options['must_staple'] ?? false;

        if (!\is_bool($mustStaple)) {
            throw new \TypeError(sprintf('$mustStaple must be of type bool, %s given', gettype($mustStaple)));
        }

        $this->mustStaple = $mustStaple;
    }

    /** @inheritdoc */
    public function generateCsr(PrivateKey $key, array $domains): Promise {
        return call(function () use ($key, $domains) {
            if (!$privateKey = openssl_pkey_get_private($key->toPem())) {
                throw new CryptoException('OpenSSL considered the private key invalid.');
            }

            if (!$domains) {
                throw new AcmeException("Parameter \$domains must not be empty.");
            }

            try {
                $i = 0;

                $san = implode(',', array_map(function ($dns) use (&$i) {
                    // throws on invalid DNS names
                    $dns = normalizeDnsName($dns);

                    return "DNS:{$dns}";
                }, $domains));
            } catch (InvalidDnsNameException $e) {
                throw new AcmeException('Invalid domain name: ' . $e->getMessage());
            }

            // http://www.heise.de/netze/rfc/rfcs/rfc7633.shtml
            // http://www.heise.de/netze/rfc/rfcs/rfc6066.shtml
            $mustStaple = $this->mustStaple ? 'tlsfeature = status_request' : '';

            $tempFile = tempnam(sys_get_temp_dir(), 'acme-openssl-config-');
            $tempConf = <<<EOL
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
{$mustStaple}

[ req_distinguished_name ]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = {$san}
EOL;

            yield File\put($tempFile, $tempConf);

            try {
                \set_error_handler(function ($errno, $errstr) {
                    throw new CryptoException($errstr);
                });

                $csr = openssl_csr_new([
                    'CN' => reset($domains),
                ], $privateKey, [
                    'digest_alg' => 'sha256',
                    'req_extensions' => 'v3_req',
                    'config' => $tempFile,
                ]);
            } finally {
                \restore_error_handler();
            }

            yield File\unlink($tempFile);

            if (!$csr) {
                throw new AcmeException('A CSR resource could not be generated.');
            }

            if (!openssl_csr_export($csr, $csrOut)) {
                throw new AcmeException('A CSR resource could not be exported as a string.');
            }

            return $csrOut;
        });
    }
}
