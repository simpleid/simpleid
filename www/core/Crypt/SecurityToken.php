<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2026
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

namespace SimpleID\Crypt;

use Branca\Branca;
use JsonException;
use SimpleID\Store\StoreManager;

/**
 * A security token generator based on the branca token specification.
 *
 * A security token contains signed and encrypted data which only the
 * generator can decode.  It is used for various purposes, such as:
 *
 * - encoding state data to be passed between HTTP requests
 * - generating CSRF tokens
 * 
 * The payload of the token is a JSON object with the following
 * keys defined:
 * 
 * - `i` - a random generated identifier for the token
 * - `o` - token options, consisting of the sum of the OPTION_
 *   constants defined by this class
 * - `p` - the payload
 * - `s` (optional) - the session ID
 * 
 * @see https://github.com/tuupola/branca-spec
 */
class SecurityToken {
    /** @var string */
    static private $site_token = null;

    const OPTION_DEFAULT = 0;

    /** The security token is bound to the current session ID */
    const OPTION_BIND_SESSION = 1;

    /** The security token can only be verified once */
    const OPTION_NONCE = 2;

    /** @var Branca the branca token generator */
    private $branca;

    /** @var array<string, mixed> the data (i.e. payload plus headers) to be encoded in
     * the token */
    private $data = null;

    /**
     * Creates a token generator.
     *
     * The encryption and signing keys should be formatted as a 32-byte
     * binary string
     *
     * @param string $key the encryption and signing keys as a base64url
     * encoded string
     */
    function __construct($key = null) {
        if ($key == null) {
            if (self::$site_token === null) self::$site_token = (StoreManager::instance())->getKey('site-token');
            $key = self::$site_token;
        }

        // Decode from base64url
        $this->branca = new Branca(base64_decode(strtr($key, '-_', '+/')));
    }

    /**
     * Checks whether the token string is valid and if so, obtains the payload.
     *
     * @param string $token the token string
     * @param int $ttl the number of seconds from which the token is considered
     * expired
     * @return mixed the payload or NULL if the security token is not valid
     */
    public function getPayload($token, $ttl = null) {
        try {
            $message = $this->branca->decode($token, $ttl);
        } catch (\RuntimeException $e) {
            return null;
        }

        $decompressed = gzuncompress($message);
        if ($decompressed == false) return null;

        $this->data = json_decode($decompressed, true);

        if (($this->data['o'] & self::OPTION_BIND_SESSION) == self::OPTION_BIND_SESSION) {
            if (!isset($this->data['s'])) return null;
            if ($this->data['s'] != session_id()) return null;
        }

        if (($this->data['o'] & self::OPTION_NONCE) == self::OPTION_NONCE) {
            if (!isset($this->data['i'])) return null;

            $cache = \Cache::instance();
            $cache_name = rawurlencode($this->data['i']) . '.token';

            if (!$cache->exists($cache_name)) return null;
            $cache_token = $cache->get($cache_name);
            $cache->clear($cache_name);
            if ($token != $cache_token) return null;
        }

        if (!isset($this->data['p'])) return null;
        return $this->data['p'];
    }

    /**
     * Convenience function to verify a token whose payload is a simple
     * string
     *
     * @param string $token the token string
     * @param string $expected the expected payload
     * @param int $ttl the number of seconds from which the token is considered
     * expired
     * @return bool true if the token is valid and the payload matches the expected
     * string
     */
    public function verify($token, $expected, $ttl = null) {
        return ($this->getPayload($token, $ttl) == $expected);
    }

    /**
     * Generates a token.
     * 
     * Note that as part of creating the token, `$payload` is encoded using
     * `json_encode()`.  Therefore `$payload` must be capable of being
     * JSON encoded.  In particular, all strings within `$payload` must be
     * UTF-8 encoded.
     *
     * @param mixed $payload the payload to include in the token
     * @param int $options the options for generating the token
     * @return string the token string
     */
    public function generate($payload, $options = self::OPTION_DEFAULT) {
        $rand = new Random();
        $this->data = [
            'i' => $rand->id(),
            'o' => $options,
            'p' => $payload
        ];
        if (($options & self::OPTION_BIND_SESSION) == self::OPTION_BIND_SESSION) {
            $this->data['s'] = session_id();
        }

        try {
            $encoded = json_encode($this->data, JSON_THROW_ON_ERROR);

            $compressed = gzcompress($encoded);
            if ($compressed == false) return new \RuntimeException();

            $token = $this->branca->encode($compressed);

            if (($options & self::OPTION_NONCE) == self::OPTION_NONCE) {
                $cache = \Cache::instance();
                $cache_name = rawurlencode($this->data['i']) . '.token';
                $cache->set($cache_name, $token, SIMPLEID_HUMAN_TOKEN_EXPIRES_IN);
            }

            return $token;
        } catch (\JsonException $e) {
            return new \RuntimeException($e->getMessage(), 0, $e);
        }
    }
}

?>