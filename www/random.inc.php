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
 * 
 * $Id$
 */

/**
 * Functions related to generating random bits and unique values.
 *
 * @package simpleid
 * @since 0.8
 * @filesource
 */

if (!defined('SIMPLEID_RAND_SOURCE')) {
    /**
     * The source of random bits.  On Unix-like systems, this could be /dev/random
     * or /dev/urandom
     */
    define('SIMPLEID_RAND_SOURCE', '/dev/urandom');
}

/**
 * Obtains a number of random bytes.  This function uses an entropy source specified
 * in SIMPLEID_RAND_SOURCE.  If SIMPLEID_RAND_SOURCE is not available, the mt_rand()
 * PHP function is used
 *
 * @param int $num_bytes the number of bytes to generate
 * @return string a string containing random bytes
 */
function random_bytes($num_bytes)
{
    static $f = null;
    $bytes = '';
    if ($f === null) {
        if (SIMPLEID_RAND_SOURCE === null) {
            $f = false;
        } else {
            $f = @fopen(SIMPLEID_RAND_SOURCE, "r");
        }
    }
    if ($f === false) {
        $bytes = '';
        for ($i = 0; $i < $num_bytes; $i += 4) {
            $bytes .= pack('L', mt_rand());
        }
        $bytes = substr($bytes, 0, $num_bytes);
    } else {
        $bytes = fread($f, $num_bytes);
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
function random_secret($num_bytes = 32)
{
    return strtr(
        base64_encode(random_bytes($num_bytes)),
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
        '-_.9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA'
    );
}

/**
 * Generates a relatively unique identifier which can be used as, among other things,
 * an OpenID association handle or an OAuth client identifier.  The identifier
 * returned is at least 24 characters long and contains only hexadecimal characters.
 *
 * Note that the identifier returned is not cryptographically secure.
 *
 * @return string a relatively unique identifier
 */
function random_id()
{
    $timeofday = gettimeofday();
    return vsprintf('%08x%08x', $timeofday) . bin2hex(random_bytes(4));
}
