<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

use Amp\Http\Client\Response;
use InvalidArgumentException;
use Kelunik\Acme\Protocol\Account;
use Kelunik\Acme\Protocol\Authorization;
use Kelunik\Acme\Protocol\Challenge;
use Kelunik\Acme\Protocol\ChallengeStatus;
use Kelunik\Acme\Protocol\Order;
use Kelunik\Acme\Protocol\OrderStatus;
use Kelunik\Certificate\Certificate;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface as PsrLogger;
use Psr\Log\NullLogger;
use function Amp\delay;

/**
 * High level ACME client.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class AcmeService
{
    /**
     * @var AcmeClient low level ACME client
     */
    private AcmeClient $client;

    private PsrLogger $logger;

    public function __construct(AcmeClient $client, ?PsrLogger $logger = null)
    {
        $this->client = $client;
        $this->logger = $logger ?? new NullLogger;
    }

    /**
     * Registers a new account on the server.
     *
     * @param string $email e-mail address for contact
     *
     * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.3
     */
    public function register(string $email, bool $agreement = false): Account
    {
        $this->logger->info('Creating new account with email ' . $email);

        $response = $this->client->post(AcmeResource::NEW_ACCOUNT, [
            'termsOfServiceAgreed' => $agreement,
            'contact' => [
                "mailto:{$email}",
            ],
        ]);

        if (\in_array($response->getStatus(), [200, 201], true)) {
            return Account::fromResponse($response->getHeader('location'), $response->getBody()->buffer());
        }

        throw $this->generateException($response, $response->getBody()->buffer());
    }

    /**
     * Retrieves existing order using the order's location URL.
     */
    public function getOrder(UriInterface $url): Order
    {
        $this->logger->info('Retrieving order ' . $url);

        $response = $this->client->post($url, null);

        if ($response->getStatus() === 200) {
            return Order::fromResponse($url, $response->getBody()->buffer());
        }

        throw $this->generateException($response, $response->getBody()->buffer());
    }

    /**
     * Submit a new order for the given DNS names.
     *
     * @param string[]                $domainNames DNS names to request order for
     * @param \DateTimeInterface|null $notBefore The requested value of the notBefore field in the certificate
     * @param \DateTimeInterface|null $notAfter The requested value of the notAfter field in the certificate
     */
    public function newOrder(
        array $domainNames,
        ?\DateTimeInterface $notBefore = null,
        ?\DateTimeInterface $notAfter = null
    ): Order {
        $this->logger->info('Creating new order for ' . \implode(', ', $domainNames));

        $request = [
            'identifiers' => [],
        ];

        foreach ($domainNames as $domainName) {
            $request['identifiers'][] = ['type' => 'dns', 'value' => $domainName];
        }

        if ($notBefore) {
            $request['notBefore'] = formatDate($notBefore);
        }

        if ($notAfter) {
            $request['notAfter'] = formatDate($notAfter);
        }

        $response = $this->client->post(AcmeResource::NEW_ORDER, $request);

        if ($response->getStatus() === 201) {
            return Order::fromResponse($response->getHeader('location'), $response->getBody()->buffer());
        }

        throw $this->generateException($response, $response->getBody()->buffer());
    }

    /**
     * Finalizes a challenge and signals that the CA should validate it.
     *
     * @param UriInterface $url URI of the challenge
     */
    public function finalizeChallenge(UriInterface $url): Challenge
    {
        $this->logger->info('Finalizing challenge ' . $url);

        $response = $this->client->post($url, []);

        try {
            return Challenge::fromResponse($response->getBody()->buffer());
        } catch (\Throwable $_) {
            throw $this->generateException($response, $response->getBody()->buffer());
        }
    }

    /**
     * Gets the authorization.
     */
    public function getAuthorization(UriInterface $url): Authorization
    {
        $this->logger->info('Retrieving authorization ' . $url);

        $response = $this->client->post($url, null);

        try {
            return Authorization::fromResponse($url, $response->getBody()->buffer());
        } catch (\Throwable $_) {
            throw $this->generateException($response, $response->getBody()->buffer());
        }
    }

    /**
     * Gets the challenge.
     */
    public function getChallenge(UriInterface $url): Challenge
    {
        $this->logger->info('Retrieving challenge ' . $url);

        $response = $this->client->post($url, null);

        try {
            return Challenge::fromResponse($response->getBody()->buffer());
        } catch (\Throwable $_) {
            throw $this->generateException($response, $response->getBody()->buffer());
        }
    }

    /**
     * Polls until a challenge has been validated.
     *
     * @param UriInterface $url URI of the authorization
     */
    public function pollForAuthorization(UriInterface $url): void
    {
        $this->logger->info('Polling for authorization ' . $url);

        do {
            $authorization = $this->getAuthorization($url);

            $this->logger->info('Retrieved authorization ' . $url . ': ' . $authorization->getStatus());

            if ($authorization->getStatus() === ChallengeStatus::INVALID) {
                // TODO Use Challenge->getError
                throw new AcmeException('Authorization marked as invalid.');
            }

            if ($authorization->getStatus() === ChallengeStatus::VALID) {
                break;
            }

            delay(3);
        } while (true);
    }

    /**
     * Polls until an order is ready.
     *
     * @param UriInterface $url URI of the order
     */
    public function pollForOrderReady(UriInterface $url): void
    {
        $this->logger->info('Polling for order to be ready ' . $url);

        do {
            $order = $this->getOrder($url);

            $this->logger->info('Retrieved order ' . $url . ': ' . $order->getStatus());

            if ($order->getStatus() === OrderStatus::INVALID) {
                // TODO Use Challenge->getError
                throw new AcmeException('Order marked as invalid.');
            }

            if ($order->getStatus() === OrderStatus::READY) {
                break;
            }

            delay(3);
        } while (true);
    }

    /**
     * Polls until an order is valid.
     *
     * @param UriInterface $url URI of the order
     */
    public function pollForOrderValid(UriInterface $url): void
    {
        $this->logger->info('Polling for order to be valid ' . $url);

        do {
            $order = $this->getOrder($url);

            $this->logger->info('Retrieved order ' . $url . ': ' . $order->getStatus());

            if ($order->getStatus() === OrderStatus::INVALID) {
                // TODO Use Challenge->getError
                throw new AcmeException('Order marked as invalid.');
            }

            if ($order->getStatus() === OrderStatus::VALID) {
                break;
            }

            delay(3);
        } while (true);
    }

    /**
     * Requests a new certificate. This will be done with the finalize URL which is created upon order creation.
     *
     * @param string       $csr certificate signing request
     */
    public function finalizeOrder(UriInterface $url, string $csr): Order
    {
        $this->logger->info('Finalizing order ' . $url);

        $begin = 'REQUEST-----';
        $end = '----END';

        $beginPos = \strpos($csr, $begin);
        if ($beginPos === false) {
            throw new InvalidArgumentException("Invalid CSR, maybe not in PEM format?\n{$csr}");
        }

        $csr = \substr($csr, $beginPos + \strlen($begin));

        $endPos = \strpos($csr, $end);
        if ($endPos === false) {
            throw new InvalidArgumentException("Invalid CSR, maybe not in PEM format?\n{$csr}");
        }

        $csr = \substr($csr, 0, $endPos);

        /** @var Response $response */
        $response = $this->client->post($url, [
            'csr' => base64UrlEncode(\base64_decode($csr)),
        ]);

        if ($response->getStatus() === 200) {
            return Order::fromResponse($response->getHeader('location'), $response->getBody()->buffer());
        }

        throw $this->generateException($response, $response->getBody()->buffer());
    }

    /**
     * Downloads the certificate (and parent certificates).
     *
     * @param UriInterface $url URI of the certificate
     *
     * @return Certificate[] Complete certificate chain as array of PEM encoded certificates
     */
    public function downloadCertificates(UriInterface $url): array
    {
        $this->logger->info('Downloading certificate ' . $url);

        $response = $this->client->post($url, null);

        if ($response->getStatus() === 200) {
            $certificateChain = $response->getBody()->buffer();
            $certificates = [];

            while (\preg_match(
                '(-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----)si',
                $certificateChain,
                $match
            )) {
                $certificateChain = \str_replace($match[0], '', $certificateChain);
                $certificate = Certificate::derToPem(Certificate::pemToDer($match[0]));

                $certificates[] = $certificate;
            }

            return $certificates;
        }

        throw $this->generateException($response, $response->getBody()->buffer());
    }

    /**
     * Revokes a certificate.
     *
     * @param string $pem PEM encoded certificate
     */
    public function revokeCertificate(string $pem): void
    {
        $this->logger->info('Revoking certificate ' . $pem);

        $response = $this->client->post(AcmeResource::REVOKE_CERTIFICATE, [
            'certificate' => base64UrlEncode(Certificate::pemToDer($pem)),
        ]);

        if ($response->getStatus() === 200) {
            return;
        }

        throw $this->generateException($response, $response->getBody()->buffer());
    }

    /**
     * Parses a retry header into seconds to wait until a request should be retried.
     *
     * @param string $header header value
     *
     * @return int seconds to wait until retry
     * @throws AcmeException If the header value cannot be parsed.
     */
    private function parseRetryAfter(string $header): int
    {
        if (\preg_match('#^\d+$#', $header)) {
            return (int) $header;
        }

        $time = @\strtotime($header);

        if ($time === false) {
            throw new AcmeException("Invalid retry-after header: '{$header}'");
        }

        return \max($time - \time(), 0);
    }

    /**
     * Generates a new exception using the response to provide details.
     *
     * @param Response $response HTTP response to generate the exception from.
     * @param string   $body HTTP response body.
     *
     * @return AcmeException exception generated from the response body
     */
    private function generateException(Response $response, string $body): AcmeException
    {
        $status = $response->getStatus();
        $info = \json_decode($body);
        $uri = $response->getRequest()->getUri();

        if (isset($info->type, $info->detail)) {
            return new AcmeException("Invalid response: {$info->detail}.\nRequest URI: {$uri}.", $info->type);
        }

        return new AcmeException("Invalid response: {$body}.\nRequest URI: {$uri}.", $status);
    }
}
