<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2017, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

/**
 * Collection of ACME error codes.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
final class AcmeError
{
    /**
     * Non existing account:
     * (RFC8555) The request specified an account that does not exist.
     */
    public const TYPE_ACCOUNT_NON_EXISTS = 'accountDoesNotExist';

    /**
     * Already revoked:
     * (RFC8555) The request specified a certificate to be revoked that has already been revoked.
     */
    public const TYPE_ALREADY_REVOKED = 'alreadyRevoked';

    /**
     * Bad CSR:
     * (RFC8555) The CSR is unacceptable (e.g., due to a short key).
     */
    public const TYPE_BAD_CSR = 'badCSR';

    /**
     * Bad replay nonce:
     * (RFC8555) The client sent an unacceptable anti-replay nonce.
     */
    public const TYPE_BAD_NONCE = 'badNonce';

    /**
     * Bad public key:
     * (RFC8555) The JWS was signed by a public key the server does not support.
     */
    public const TYPE_BAD_PUBLIC_KEY = 'badPublicKey';

    /**
     * Bad revocation reason:
     * (RFC8555) The revocation reason provided is not allowed by the server.
     */
    public const TYPE_BAD_REVOCATION_REASON = 'badRevocationReason';

    /**
     * Bad signature algorithm:
     * (RFC8555) The JWS was signed with an algorithm the server does not support.
     */
    public const TYPE_BAD_SIGNATURE_ALG = 'badSignatureAlgorithm';

    /**
     * caa:
     * (RFC8555) Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate.
     */
    public const TYPE_CAA = 'caa';

    /**
     * Compound:
     * (RFC8555) Specific error conditions are indicated in the "subproblems" array.
     */
    public const TYPE_COMPOUND = 'compound';

    /**
     * Connection error:
     * (RFC8555) The server could not connect to a validation target.
     */
    public const TYPE_CONNECTION = 'connection';

    /**
     * Error related to DNS:
     * (RFC8555) There was a problem with a DNS query during identifier validation.
     */
    public const TYPE_DNS = 'dns';

    /**
     * External account required:
     * (RFC8555) The request must include a value for the "externalAccountBinding" field.
     *
     */
    public const TYPE_EXTERNAL_ACCOUNT_REQUIRED = 'externalAccountRequired';

    /**
     * Incorrect response:
     * (RFC8555) Response received didn't match the challenge's requirements.
     */
    public const TYPE_INCORRECT_RESPONSE = 'incorrectResponse';

    /**
     * Invalid contact:
     * (RFC8555) A contact URL for an account was invalid.
     */
    public const TYPE_INVALID_CONTACT = 'invalidContact';

    /**
     * Malformed request:
     * (RFC8555) The request message was malformed.
     */
    public const TYPE_MALFORMED = 'malformed';

    /**
     * Order not ready:
     * (RFC8555) The request attempted to finalize an order that is not ready to be finalized.
     */
    public const TYPE_ORDER_NOT_READY = 'orderNotReady';

    /**
     * Rate limit exceeded:
     * (RFC8555) The request exceeds a rate limit.
     */
    public const TYPE_RATE_LIMITED = 'rateLimited';

    /**
     * Rejected identifier: The server will not issue certificates for the identifier
     * (RFC8555):.
     */
    public const TYPE_REJECTED_IDENTIFIER = 'rejectedIdentifier';

    /**
     * Internal server error:
     * (RFC8555) The server experienced an internal error.
     */
    public const TYPE_SERVER_INTERNAL = 'serverInternal';

    /**
     * TLS error.
     * (RFC8555) The server received a TLS error during validation.
     */
    public const TYPE_TLS = 'tls';

    /**
     * Unauthorized:
     * (RFC8555) The client lacks sufficient authorization.
     */
    public const TYPE_UNAUTHORIZED = 'unauthorized';

    /**
     * Unsupported contact:
     * (RFC8555) A contact URL for an account used an unsupported protocol scheme.
     */
    public const TYPE_UNSUPPORTED_CONTACT = 'unsupportedContact';

    /**
     * Unsupported identifier:
     * (RFC8555) An identifier is of an unsupported type.
     */
    public const TYPE_UNSUPPORTED_IDENTIFIER = 'unsupportedIdentifier';

    /**
     * User action required:
     * (RFC8555) Visit the "instance" URL and take actions specified there.
     */
    public const TYPE_USER_ACTION_REQUIRED = 'userActionRequired';
}
