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

final class Account
{
    public static function fromResponse(?string $url, string $payload): Account
    {
        if ($url === null) {
            throw new AcmeException('Missing account URL');
        }

        return new self(Http::createFromString($url), ...parseResponse($payload, [
            'status' => enum(AccountStatus::getAll()),
            'contact' => multiple(contact(), true),
            'orders' => optional(url()),
        ]));
    }

    /**
     * @var UriInterface URI of the account object.
     */
    private UriInterface $url;

    /**
     * @var string The status of this account.
     */
    private string $status;

    /**
     * @var array All contacts registered with the server.
     */
    private array $contacts;

    /**
     * @var null|UriInterface An url to fetch orders for this registration from
     */
    private ?UriInterface $ordersUrl;

    /**
     * Account constructor.
     *
     * @param UriInterface      $url URI of the registration object.
     * @param string            $status The status of this account.
     * @param array             $contact All contacts registered with the server.
     * @param UriInterface|null $ordersUrl An url to fetch orders for this registration from
     */
    public function __construct(UriInterface $url, string $status, array $contact = [], ?UriInterface $ordersUrl = null)
    {
        $this->url = $url;
        $this->status = $status;
        $this->contacts = $contact;
        $this->ordersUrl = $ordersUrl;
    }

    /**
     * Gets the account URL.
     *
     * @return UriInterface URL to retrieve this registration object
     */
    public function getUrl(): UriInterface
    {
        return $this->url;
    }

    /**
     * Gets the account status.
     *
     * @return string Status of this account.
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * Gets the contact addresses.
     *
     * @return array Contacts registered with the server.
     */
    public function getContacts(): array
    {
        return $this->contacts;
    }

    /**
     * Gets the order URI from which the orders of this account can be fetched.
     *
     * @return null|UriInterface URI to fetch orders from
     */
    public function getOrdersUrl(): ?UriInterface
    {
        return $this->ordersUrl;
    }
}
