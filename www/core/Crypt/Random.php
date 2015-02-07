<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2010
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

if (!defined('SIMPLEID_RAND_SOURCE')) {
    /**
     * The source of random bits.  On Unix-like systems, this could be /dev/random
     * or /dev/urandom
     */
    define('SIMPLEID_RAND_SOURCE', '/dev/urandom');
}

/**
 * Functions related to generating random bits and unique values.
 *
 * @since 0.8
 */
class Random {

    /**
     * Obtains a number of random bytes.  This function uses an entropy source specified
     * in SIMPLEID_RAND_SOURCE.  If SIMPLEID_RAND_SOURCE is not available, the mt_rand()
     * PHP function is used
     *
     * @param int $num_bytes the number of bytes to generate
     * @return string a string containing random bytes
     */
    static function bytes($num_bytes) {
        $is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
        
        if ($is_windows) {
            // Windows
            if (function_exists('mcrypt_create_iv') && version_compare(PHP_VERSION, '5.3.0', '>=')) 
                return mcrypt_create_iv($num_bytes);

            if (function_exists('openssl_random_pseudo_bytes') && version_compare(PHP_VERSION, '5.3.4', '>='))
                return openssl_random_pseudo_bytes($num_bytes);
        }

        if (!$is_windows && function_exists('openssl_random_pseudo_bytes'))
            return openssl_random_pseudo_bytes($num_bytes);

        $bytes = '';
        if ($f === null) {
            if (SIMPLEID_RAND_SOURCE === null) {
                $f = FALSE;
            } else {
                $f = @fopen(SIMPLEID_RAND_SOURCE, "r");
            }
        }
        if ($f === FALSE) {
            $bytes = '';
            for ($i = 0; $i < $num_bytes; $i += 4) {
                $bytes .= pack('L', mt_rand());
            }
            $bytes = substr($bytes, 0, $num_bytes);
        } else {
            $bytes = fread($f, $num_bytes);
            fclose($f);
        }
        return $bytes;
    }

    /**
     * Obtains a random string of a specified number of bytes of entropy.
     *
     * The function calls the {@link random_bytes()} function with the specified
     * number of bytes, then converts to a string containing only alphanumeric
     * characters (case sensitive), plus the characters ., _ and -.
     *
     * The conversion method is based on the Base64 encoding.  However, non-standard
     * characters are used so that users are not confused and attempt to decode
     * the returned string.
     *
     * @param int $num_bytes the approximate number of bytes of entropy in the
     * random string
     * @return string the random string
     */
    function secret($num_bytes = 32) {
        return strtr(trim(base64_encode(self::bytes($num_bytes)), '='), '+/', '-_');
    }

    /**
     * Generates a relatively unique identifier which can be used as, among other things,
     * an OpenID association handle or an OAuth client identifier.
     *
     * Note that the identifier returned is not cryptographically secure.
     *
     * @return string a relatively unique identifier
     */
    function id() {
        $timeofday = gettimeofday();
        $base = pack('NN', $timeofday['sec'], $timeofday['usec']) . self::bytes(32);
        return strtr(trim(base64_encode(sha1($base, true)), '='), '+/', '-_');
    }

    /**
     * Generates a nonce for use in OpenID responses
     *
     * @return string an OpenID nonce
     * @link http://openid.net/specs/openid-authentication-2_0.html#positive_assertions
     */
    function openIDNonce() {
        return gmstrftime('%Y-%m-%dT%H:%M:%SZ') . bin2hex(self::bytes(4));
    }
}
?>
