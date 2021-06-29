<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Crypto\Backend;

use Kelunik\Acme\AcmeException;
use Kelunik\Acme\Crypto\PrivateKey;
use Kelunik\Acme\Crypto\CryptoException;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;

final class OpensslBackend implements Backend {
    private $encoder;

    public function __construct() {
        $this->encoder = new Base64UrlSafeEncoder;
    }

    /**
     * Creates a "jwK" (JSON Web Key)
     * @return array
     * @throws \Kelunik\Acme\Crypto\CryptoException
     * @param \Kelunik\Acme\Crypto\PrivateKey $privateKey
     * @see https://tools.ietf.org/html/rfc7517
     */
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

    /**
     * Generates a signed JWS request for a POST or POST-as-GET request.
     * If accountUrl is provided, it uses the 'kid' field. Otherwise it uses the jwk.
     * @return string
     * @throws \Kelunik\Acme\Crypto\CryptoException
     * @throws \Kelunik\Acme\AcmeException
     * @param array $payload
     * @param string|null $accountUrl
     * @param \Kelunik\Acme\Crypto\PrivateKey $privateKey
     * @param string $nonce
     */
    public function signJwt(PrivateKey $privateKey, string $nonce, array $payload, string $accountUrl = null): string {
        if(!isset($payload)) {
            throw new AcmeException("Payload URL is not set");
        }

        $url = $payload['url'];
        unset($payload['url']);
        
        $jws = [
            'alg' => 'RS256',
            'url' => $url,
            'nonce' => $nonce,
            ($accountUrl ? 'kid' : 'jwk') => ($accountUrl ?? $this->toJwk($privateKey))
        ];
        
        $protected = $this->encoder->encode(json_encode($jws));
        if(!empty($payload)) {
            $payload = $this->encoder->encode(json_encode($payload));
        } else {
            $payload = '';
        }

        openssl_sign("$protected.$payload", $signed, $privateKey->toPem(), "SHA256");
        return json_encode([
            'protected' => $protected,
            'payload' => $payload,
            'signature' => $this->encoder->encode($signed)
        ]);
    }
}