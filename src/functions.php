<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Assert\Assert;
use Kelunik\Acme\Crypto\Backend\Backend;
use Kelunik\Acme\Crypto\PrivateKey;
use League\Uri\Http;
use Psr\Http\Message\UriInterface;

/**
 * Generates the a key authorization, which must be provided in challenges, e.g. directly in HTTP-01
 * and further encoded for DNS-01.
 *
 * @param PrivateKey $accountKey Account key pair.
 * @param string     $token Challenge token.
 * @param Backend    $cryptoBackend Crypto backend.
 *
 * @return string Key authorization.
 * @api
 *
 * @see https://tools.ietf.org/html/rfc8555#section-8.4
 */
function generateKeyAuthorization(PrivateKey $accountKey, string $token, Backend $cryptoBackend): string
{
    $jwk = $cryptoBackend->toJwk($accountKey);
    \ksort($jwk);

    return $token . '.' . base64UrlEncode(\hash('sha256', \json_encode($jwk), true));
}

/**
 * Encodes a key authorization for use in the DNS-01 challenge as TXT payload.
 *
 * @param string $keyAuthorization Key authorization generated using `generateKeyAuthorization()`.
 *
 * @return string Base64Url-encoded SHA256 digest of the `$keyAuthorization`.
 *
 * @api
 *
 * @see https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-7.5
 */
function generateDns01Payload(string $keyAuthorization): string
{
    return base64UrlEncode(\hash('sha256', $keyAuthorization, true));
}

function base64UrlEncode(string $payload): string
{
    return \rtrim(\strtr(\base64_encode($payload), '+/', '-_'), '=');
}

function parseDate(?string $date): ?\DateTimeImmutable
{
    if ($date === null) {
        return null;
    }

    $dateTime = \DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.uP', $date);
    if ($dateTime === null) {
        throw new AcmeException('Invalid date format: ' . $date);
    }

    return $dateTime;
}

function formatDate(\DateTimeInterface $date): string
{
    return $date->format('Y-m-d\TH:i:s.uP');
}

function parseUrl(?string $url): UriInterface
{
    Assert::that($url)->url();

    return Http::createFromString($url);
}
