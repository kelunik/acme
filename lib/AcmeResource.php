<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

/**
 * Collection of ACME resources.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
class AcmeResource {
    /**
     * New registration.
     */
    const NEW_REGISTRATION = "new-reg";

    /**
     * Recover registration.
     */
    const RECOVER_REGISTRATION = "recover-reg";

    /**
     * New authorization.
     */
    const NEW_AUTHORIZATION = "new-authz";

    /**
     * New certificate.
     */
    const NEW_CERTIFICATE = "new-cert";

    /**
     * Revoke certificate.
     */
    const REVOKE_CERTIFICATE = "revoke-cert";

    /**
     * Registration.
     */
    const REGISTRATION = "reg";

    /**
     * Authorization.
     */
    const AUTHORIZATION = "authz";

    /**
     * Challenge.
     */
    const CHALLENGE = "challenge";

    /**
     * Certificate.
     */
    const CERTIFICATE = "cert";
}