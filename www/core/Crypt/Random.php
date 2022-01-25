<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2010-2022
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
     * Obtains a number of random bytes using the native `random_bytes()` function.
     *
     * @param int $num_bytes the number of bytes to generate
     * @return string a string containing random bytes
     */
    static function bytes($num_bytes) {
        return random_bytes($num_bytes);
    }

    /**
     * Obtains a random string of a specified number of bytes of entropy.
     *
     * The function calls the {@link bytes()} function with the specified
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
        // Current: 160 [sha1:160] => [base64: <=28]
        // nanoid: 126 [rand:126] => [base64: 21]
        // cuid: 137 [timestamp:42] [counter:21] [fingerprint:21] [random: 42] => [base36: 24]
        // cuid (slug): 44 [timestamp:11] [counter:11] [fingerprint:11] [random:11] => [base36:<=10]
        // ksuid: 160 [timestamp:32] [rand:128] => [base62:27]
        // ulid: 128 [timestamp:48] [rand:80]
        // uuid: [rand:122]
        $timeofday = gettimeofday();
        $base = pack('NN', $timeofday['sec'], $timeofday['usec']) . self::bytes(32);
        return strtr(trim(base64_encode(sha1($base, true)), '='), '+/', '-_');
    }
}
?>
