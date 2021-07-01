<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme\Protocol;

use Kelunik\Acme\AcmeException;
use League\Uri\Http;
use Psr\Http\Message\UriInterface;

final class Order
{
    public static function fromResponse(?string $url, string $payload): Order
    {
        if ($url === null) {
            throw new AcmeException('Missing order URL');
        }

        return new self(Http::createFromString($url), ...parseResponse($payload, [
            'status' => enum(OrderStatus::getAll()),
            'identifiers' => multiple(identifier()),
            'authorizations' => multiple(url()),
            'finalize' => optional(url()),
            'expires' => optional(dateTime()),
            'notBefore' => optional(dateTime()),
            'notAfter' => optional(dateTime()),
            'certificate' => optional(url()),
        ]));
    }

    /**
     * @var UriInterface The location URL of this order.
     */
    private UriInterface $url;

    /**
     * @var string The status of this order.
     */
    private string $status;

    /**
     * @var null|\DateTimeImmutable Expiry date of this order. Required when $status is "valid" or "pending"
     */
    private ?\DateTimeImmutable $expires;

    /**
     * @var Identifier[] All identifiers corresponding this order.
     */
    private array $identifiers;

    /**
     * @var UriInterface[] Authorizations each of the identifiers must met before certificate can be issued
     */
    private array $authorizationUrls;

    /**
     * @var UriInterface Finalize url to complete order once authorizations are met
     */
    private UriInterface $finalizationUrl;

    /**
     * @var null|UriInterface The certificate URL that has been issued once this order is completed.
     */
    private ?UriInterface $certificateUrl;

    private ?\DateTimeImmutable $notBefore;
    private ?\DateTimeImmutable $notAfter;

    public function __construct(
        UriInterface $url,
        string $status,
        array $identifiers,
        array $authorizationUrls,
        UriInterface $finalizationUrl,
        ?\DateTimeImmutable $expires = null,
        ?\DateTimeImmutable $notBefore = null,
        ?\DateTimeImmutable $notAfter = null,
        ?UriInterface $certificateUrl = null
    ) {
        if (!OrderStatus::isKnown($status)) {
            throw new AcmeException("Invalid order status: {$status}");
        }

        if ($expires === null && \in_array($status, [OrderStatus::PENDING, OrderStatus::VALID], true)) {
            throw new AcmeException("Expiration date is mandatory when order status is `pending` or `valid`");
        }

        $this->url = $url;
        $this->status = $status;
        $this->identifiers = $identifiers;
        $this->authorizationUrls = $authorizationUrls;
        $this->finalizationUrl = $finalizationUrl;
        $this->expires = $expires;
        $this->certificateUrl = $certificateUrl;
        $this->notBefore = $notBefore;
        $this->notAfter = $notAfter;
    }

    public function getUrl(): UriInterface
    {
        return $this->url;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * @return Identifier[]
     */
    public function getIdentifiers(): array
    {
        return $this->identifiers;
    }

    /**
     * @return UriInterface[]
     */
    public function getAuthorizationUrls(): array
    {
        return $this->authorizationUrls;
    }

    public function getFinalizationUrl(): UriInterface
    {
        return $this->finalizationUrl;
    }

    public function getExpires(): ?\DateTimeImmutable
    {
        return $this->expires;
    }

    public function getCertificateUrl(): ?UriInterface
    {
        return $this->certificateUrl;
    }

    public function getNotBefore(): ?\DateTimeImmutable
    {
        return $this->notBefore;
    }

    public function getNotAfter(): ?\DateTimeImmutable
    {
        return $this->notAfter;
    }
}
