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
 * 
 */

namespace SimpleID\Crypt;

/**
 * Compatibility class for PBKDF2 hashing.
 */
class PBKDF2 {
    
    static function hash($algo, $password, $salt, $iterations, $length = 0, $raw_output = false) {
        if (function_exists('hash_pbkdf2')) {
            return hash_pbkdf2($algo, $password, $salt, $iterations, $length, $raw_output);
        }

        $result = '';
        $hLen = strlen(hash($algo, '', true));
        if ($length == 0) {
            $length = $hLen;
            if (!$raw_output) $length *= 2;
        }
        $l = ceil($length / $hLen);

        for ($i = 1; $i <= $l; $i++) {
            $U = hash_hmac($algo, $salt . pack('N', $i), $password, true);
            $T = $U;
            for ($j = 1; $j < $iterations; $j++) {
                $T ^= ($U = hash_hmac($algo, $U, $password, true));
            }
            $result .= $T;
        }

        return substr(($raw_output) ? $result : bin2hex($result), 0, $length);
    }
}


?>