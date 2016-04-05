<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
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

    /**
     * {@inheritdoc}
     */
    public function generate(KeyPair $keyPair, array $domains) {
        if (!$privateKey = openssl_pkey_get_private($keyPair->getPrivate())) {
            // TODO: Improve error message
            throw new AcmeException("Couldn't use private key.");
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

        yield \Amp\File\put($tempFile, $tempConf . "\n" . $san . "\n");

        $csr = openssl_csr_new([
            "CN" => reset($domains),
        ], $privateKey, [
            "digest_alg" => "sha256",
            "config" => $tempFile,
        ]);

        yield \Amp\File\unlink($tempFile);

        if (!$csr) {
            // TODO: Improve error message
            throw new AcmeException("CSR could not be generated.");
        }

        yield new CoroutineResult(openssl_csr_export($csr, $csr));
    }
}