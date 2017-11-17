<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Crypto\Backend;

use Kelunik\Acme\Crypto\PrivateKey;
use Kelunik\Acme\Crypto\CryptoException;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\SimpleJWS;

final class OpensslBackend implements Backend {
    private $encoder;

    public function __construct() {
        $this->encoder = new Base64UrlSafeEncoder;
    }

    public function toJwk(PrivateKey $privateKey): array {
        $key = \openssl_pkey_get_private($privateKey->toPem());

        if (!$key) {
            throw new CryptoException("Couldn't read private key.");
        }

        $details = \openssl_pkey_get_details($key);

        if ($details['type'] !== \OPENSSL_KEYTYPE_RSA) {
            throw new CryptoException('Unsupported key type, currently only RSA is supported.');
        }

        return [
            'e' => $this->encoder->encode($details['rsa']['e']),
            'kty' => 'RSA',
            'n' => $this->encoder->encode($details['rsa']['n']),
        ];
    }

    public function signJwt(PrivateKey $privateKey, string $nonce, array $payload): string {
        $jws = new SimpleJWS([
            'alg' => 'RS256',
            'jwk' => $this->toJwk($privateKey),
            'nonce' => $nonce,
        ]);

        $jws->setPayload($payload);
        $jws->sign($privateKey->toPem());

        return $jws->getTokenString();
    }
}