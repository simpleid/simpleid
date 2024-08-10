<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2024
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

namespace SimpleID\Util;

use SimpleID\Crypt\Random;
use SimpleID\Store\StoreManager;

/**
 * A generator and verifier of opaque identifier tokens.
 *
 * An opaque identifer token is a string which identifies something in SimpleID
 * (e.g. a user), but encoded so that it provides no information to the
 * recipient about the thing it identifies.
 *
 * An opaque identifier is generated by encoding a SimpleID identifier with
 * a context array.  The context array contains recipient-specific data so that
 * the opaque identifier is bound to the recipient.
 */
class OpaqueIdentifier {
    /** @var string */
    static private $opaque_token = null;

    function __construct() {
        if (self::$opaque_token === null) self::$opaque_token = self::getOpaqueToken();
    }

    /**
     * Verifies whether an opaque identifier token matches a specified identifier.
     *
     * @param string $token the identifier token
     * @param string $expected_id the expected identifier
     * @param array<mixed> $context additional data that have been encoded
     * @return bool true if the identifier token matches the expected identifier
     */
    public function verify($token, $expected_id, $context = []) {
        return ($this->generate($expected_id, $context) == $token);
    }

    /**
     * Generates an opaque identifier token
     *
     * @param string $id the identifier to encode
     * @param array<mixed> $context additional data to encode
     * @return string the opaque identifier token
     */
    public function generate($id, $context = []) {
        $base_string = $id . ' ' . $this->formatArray($context);
        $hash = hash_hmac('sha256', $base_string, self::$opaque_token, true);
        return trim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }


    /**
     * Converts an array into a string.  The array must be a single
     * dimension with string values.
     *
     * @param array<string, string> $array the array the convert
     * @return string the converted string
     */
    protected function formatArray($array) {
        $output = [];

        ksort($array);
        $keys = array_keys($array);
        
        foreach ($keys as $key) {
            $output[] = $key . ": " . $array[$key];
        }
        
        return implode('; ', $output);
    }

    /**
     * Gets the site-specific key for generating identifiers.
     *
     * If the key does not exist, it is automatically generated.
     *
     * @return string site-specific key as a binary string
     */
    static private function getOpaqueToken() {
        $store = StoreManager::instance();

        $opaque_token = $store->getSetting('opaque-token');

        if ($opaque_token == NULL) {
            $rand = new Random();

            $opaque_token = $rand->bytes(16);
            $store->setSetting('opaque-token', SecureString::fromPlaintext($opaque_token));
        } else {
            if ($opaque_token instanceof SecureString) {
                $opaque_token = SecureString::getPlaintext($opaque_token);
            } else {
                $opaque_token = base64_decode($opaque_token);
            }
        }

        return $opaque_token;
    }
}