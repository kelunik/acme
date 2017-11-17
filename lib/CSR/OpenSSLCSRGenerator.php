<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\CSR;

use Amp\CoroutineResult;
use Kelunik\Acme\AcmeException;
use Kelunik\Acme\KeyPair;

/**
 * Allows generating certificate signing requests using OpenSSL.
 *
 * @package Kelunik\Acme
 */
class OpenSSLCSRGenerator implements CSRGenerator {
    private $mustStaple;

    /**
     * OpenSSLCSRGenerator constructor.
     *
     * @param array $options CSR options, currently only "must_staple" = true | false is supported
     */
    public function __construct(array $options = []) {
        $mustStaple = isset($options["must_staple"]) ? $options["must_staple"] : false;

        if (!is_bool($mustStaple)) {
            throw new \InvalidArgumentException(sprintf("\$mustStaple must be of type bool, %s given", gettype($mustStaple)));
        }

        $this->mustStaple = $mustStaple;
    }

    /** @inheritdoc */
    public function generate(KeyPair $keyPair, array $domains) {
        return \Amp\resolve(function () use ($keyPair, $domains) {
            if (!$privateKey = openssl_pkey_get_private($keyPair->getPrivate())) {
                throw new AcmeException("OpenSSL considered the private key invalid.");
            }

            if (empty($domains)) {
                throw new AcmeException("The list of domain names must not be empty.");
            }

            $san = implode(",", array_map(function ($dns) {
                return "DNS:{$dns}";
            }, $domains));

            // http://www.heise.de/netze/rfc/rfcs/rfc7633.shtml
            // http://www.heise.de/netze/rfc/rfcs/rfc6066.shtml
            $mustStaple = $this->mustStaple ? "tlsfeature = status_request" : "";

            $tempFile = tempnam(sys_get_temp_dir(), "acme-openssl-config-");
            $tempConf = <<<EOL
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
{$mustStaple}

[ req_distinguished_name ]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation
subjectAltName = {$san}
EOL;

            yield \Amp\File\put($tempFile, $tempConf);

            $csr = openssl_csr_new([
                "CN" => reset($domains),
            ], $privateKey, [
                "digest_alg" => "sha256",
                "config" => $tempFile,
            ]);

            yield \Amp\File\unlink($tempFile);

            if (!$csr) {
                throw new AcmeException("A CSR resource could not be generated.");
            }

            if (!openssl_csr_export($csr, $csrString)) {
                throw new AcmeException("A CSR resource could not be exported as a string.");
            }

            yield new CoroutineResult($csrString);
        });
    }
}
