<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2010-2025
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

use Ulid\Ulid;

/**
 * Functions related to generating random bits and unique values.
 *
 * @since 0.8
 */
class Random {

    const BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    /**
     * Obtains a number of random bytes using the native `random_bytes()` function.
     *
     * @param int<1, max> $num_bytes the number of bytes to generate
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
     * @param int<1, max> $num_bytes the approximate number of bytes of entropy in the
     * random string
     * @return string the random string
     */
    function secret($num_bytes = 32) {
        return strtr(trim(base64_encode(self::bytes($num_bytes)), '='), '+/', '-_');
    }

    /**
     * Generates a random string that can be used as a password.
     *
     * The function calls the {@link bytes()} function with the specified
     * number of characters, then converts to a string containing only alphanumeric
     * characters (case sensitive).
     * 
     * By default, the conversion method is a form of Base58 encoding, which strips
     * out confusing characters such as I, l, O and 0.  A custom encoding can be
     * specified in the `$chars` parameter.
     *
     * @param int<1, max> $num_chars the number of characters in the password
     * @param int<0, max> $group_size if greater than 0, the characters
     * are grouped into groups of this size, separated by hyphens
     * @param string $chars the set of characters to use for the password
     * @return string the random password
     */
    function password($num_chars = 18, $group_size = 0, $chars = self::BASE58_CHARS) {
        // determine mask for valid characters
        $mask = 256 - (256 % strlen($chars));

        $result = '';
        do {
            $rand = self::bytes($num_chars);
            for ($i = 0; $i < $num_chars; $i++) {
                if (ord($rand[$i]) >= $mask) continue;
                $result .= $chars[ord($rand[$i]) % strlen($chars)];
            }
        } while (strlen($result) < $num_chars);
        $result = substr($result, 0, $num_chars);

        if ($group_size > 0) {
            $grouped_result = [];
            for ($i = 0; $i < strlen($result); $i += $group_size) {
                $grouped_result[] = substr($result, $i, $group_size);
            }
            return implode('-', $grouped_result);
        } else {
            return $result;
        }
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
        return (string) Ulid::generate(true);
    }

    /**
     * Generates a short-lived code as a number with a specified number of
     * digits
     * 
     * Note that the identifier returned is not cryptographically secure.
     *
     * @param int<1, max> $num_digits the number of digits
     * @return string a short-lived code
     */
    function shortCode($num_digits = 6) {
        $base = new BigNum(self::bytes($num_digits), 256);
        $val = $base->val(10);
        assert($val != false);
        return substr($val, -$num_digits);
    }
}
?>
