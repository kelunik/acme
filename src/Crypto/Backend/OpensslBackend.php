<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Crypto\Backend;

use Kelunik\Acme\AcmeException;
use Kelunik\Acme\Crypto\CryptoException;
use Kelunik\Acme\Crypto\PrivateKey;
use function Kelunik\Acme\base64UrlEncode;

final class OpensslBackend implements Backend
{
    /**
     * Creates a JSON Web Key (jwk).
     *
     * @param PrivateKey $privateKey
     *
     * @return array
     * @throws CryptoException
     *
     * @see https://tools.ietf.org/html/rfc7517
     */
    public function toJwk(PrivateKey $privateKey): array
    {
        $key = \openssl_pkey_get_private($privateKey->toPem());

        if (!$key) {
            throw new CryptoException("Couldn't read private key.");
        }

        $details = \openssl_pkey_get_details($key);

        if ($details['type'] !== \OPENSSL_KEYTYPE_RSA) {
            throw new CryptoException('Unsupported key type, currently only RSA is supported.');
        }

        return [
            'e' => base64UrlEncode($details['rsa']['e']),
            'kty' => 'RSA',
            'n' => base64UrlEncode($details['rsa']['n']),
        ];
    }

    /**
     * Generates a signed JWS request for a POST or POST-as-GET request.
     *
     * If accountUrl is provided, it uses the 'kid' field. Otherwise it uses the jwk.
     *
     * @param array|null $payload
     * @param string|null $accountUrl
     * @param PrivateKey $privateKey
     * @param string $nonce
     *
     * @return string
     * @throws CryptoException
     * @throws AcmeException
     */
    public function signJwt(
        PrivateKey $privateKey,
        string $url,
        string $nonce,
        ?array $payload,
        ?string $accountUrl
    ): string {
        $jws = [
            'alg' => 'RS256',
            'url' => $url,
            'nonce' => $nonce,
        ];

        if ($accountUrl) {
            $jws['kid'] = $accountUrl;
        } else {
            $jws['jwk'] = $this->toJwk($privateKey);
        }

        $protected = base64UrlEncode(\json_encode($jws));

        if ($payload === null) {
            $payloadString = '';
        } else if ($payload === []) {
            $payloadString = base64UrlEncode('{}');
        } else {
            $payloadString = base64UrlEncode(\json_encode($payload));
        }

        \openssl_sign("$protected.$payloadString", $signed, $privateKey->toPem(), "SHA256");

        return \json_encode([
            'protected' => $protected,
            'payload' => $payloadString,
            'signature' => base64UrlEncode($signed),
        ], \JSON_THROW_ON_ERROR);
    }
}
