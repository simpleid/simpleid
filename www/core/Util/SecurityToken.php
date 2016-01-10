<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014
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

use Fernet\Fernet;
use SimpleID\Crypt\Random;
use SimpleID\Store\StoreManager;

/**
 * A security token generator based on the Fernet token specification.
 *
 * A security token is a string which contains signed and encrypted data
 * which only the generator can decode.  It is used for various
 * purposes, such as:
 *
 * - encoding state data to be passed between HTTP requests
 * - generating CSRF tokens
 */
class SecurityToken {

    static private $site_token = null;

    const OPTION_DEFAULT = 0;

    /** The security token is bound to the current session ID */
    const OPTION_BIND_SESSION = 1;

    /** The security token can only be verified once */
    const OPTION_NONCE = 2;

    /** @var Fernet the fernet token generator */
    private $fernet;

    /** @var array the data (i.e. payload plus headers) to be encoded in
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
            if (self::$site_token === null) self::$site_token = self::getSiteToken();
            $key = self::$site_token;
        }

        $this->fernet = new Fernet($key);
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
        $message = $this->fernet->decode($token, $ttl);
        if ($message === null) return null;

        $this->data = unserialize(gzuncompress($message));

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
     * @return true if the token is valid and the payload matches the expected
     * string
     */
    public function verify($token, $expected, $ttl = null) {
        return ($this->getPayload($token, $ttl) == $expected);
    }

    /**
     * Generates a token
     *
     * @param mixed $payload the payload to include in the token
     * @param int $options the options for generating the token
     * @return string the token string
     */
    public function generate($payload, $options = self::OPTION_DEFAULT) {
        $rand = new Random();
        $this->data = array(
            'i' => $rand->id(),
            'o' => $options,
            'p' => $payload
        );
        if (($options & self::OPTION_BIND_SESSION) == self::OPTION_BIND_SESSION) {
            $this->data['s'] = session_id();
        }

        $token = $this->fernet->encode(gzcompress(serialize($this->data)));

        if (($options & self::OPTION_NONCE) == self::OPTION_NONCE) {
            $cache = \Cache::instance();
            $cache->set($this->data['i'] . '.token', $token, SIMPLEID_HUMAN_TOKEN_EXPIRES_IN);
        }

        return $token;
    }

    /**
     * Deletes any expired tokens.
     */
    public function gc() {
        $cache = \Cache::instance();
        $cache->reset('.token', SIMPLEID_HUMAN_TOKEN_EXPIRES_IN);
    }

    /**
     * Gets the site-specific encryption and signing key.
     *
     * If the key does not exist, it is automatically generated.
     *
     * @return string the site-specific encryption and signing key
     * as a base64url encoded string
     */
    static private function getSiteToken() {
        $store = StoreManager::instance();

        $site_token = $store->getSetting('site-token');

        if ($site_token == NULL) {
            $rand = new Random();

            $site_token = Fernet::base64url_encode($rand->bytes(32));
            $store->setSetting('site-token', $site_token);
        }

        return $site_token;
    }
}

?>