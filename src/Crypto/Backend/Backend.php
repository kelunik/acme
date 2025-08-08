<?php declare(strict_types=1);

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2025, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Crypto\Backend;

use Kelunik\Acme\Crypto\PrivateKey;

interface Backend
{
    public function toJwk(PrivateKey $privateKey): array;

    public function signJwt(
        PrivateKey $privateKey,
        string $url,
        string $nonce,
        ?array $payload,
        string $accountUrl
    ): string;
}
