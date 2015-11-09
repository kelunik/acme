<?php

namespace Kelunik\Acme;

/**
 * @author Niklas Keller <me@kelunik.com>
 * @copyright Copyright (c) 2015, Niklas Keller
 * @package Kelunik\Acme
 */
class AcmeResource {
    const NEW_REGISTRATION = "new-reg";
    const RECOVER_REGISTRATION = "recover-reg";
    const NEW_AUTHORIZATION = "new-authz";
    const NEW_CERTIFICATE = "new-cert";
    const REVOKE_CERTIFICATE = "revoke-cert";
    const REGISTRATION = "reg";
    const AUTHORIZATION = "authz";
    const CHALLENGE = "challenge";
    const CERTIFICATE = "cert";
}