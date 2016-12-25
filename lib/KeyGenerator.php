<?php

/**
 * This file is part of the ACME package.
 *
 * @copyright Copyright (c) 2015-2016, Niklas Keller
 * @license MIT
 */

namespace Kelunik\Acme;

/**
 * Key generator interface to generate RSA keys.
 *
 * @author Niklas Keller <me@kelunik.com>
 * @package Kelunik\Acme
 */
interface KeyGenerator {
  /**
   * Generates a new key pair with the given length in bits or an Eliptic curve.
   *
   * @api
   * @param int|string $bits length of the key or the Eliptic curve name
   * @param $key_type int type of the key
   * @return KeyPair generated key pair
   */
  public function generate($bits, $key_type);
}
