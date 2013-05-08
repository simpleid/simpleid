<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2009
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
 * Abstraction library for multiple precision mathematics.  This file uses either
 * the GNU Multiple Precision Arithmic Libary (GMP) if it is installed, or the
 * default BCMath library if it is not installed.
 *
 * @package simpleid
 * @filesource
 */

 
if (function_exists('gmp_init')) {
    /**
     * Defines whether the GMP library is available.
     */
    define('BIGNUM_GMP', true);
} else {
    /** @ignore */
    define('BIGNUM_GMP', false);
}

/**
 * Returns whether either the GMP or the BCMath library is installed.  If neither
 * of these libraries are installed, the functions in this file will not work.
 *
 * @return bool true if either GMP or BCMath is installed.
 */ 
function bignum_loaded() {
    return (function_exists('gmp_init') || function_exists('bcadd'));
}

/**
 * Creates a bignum.
 *
 * @param mixed $str An integer, a string in base 10, or a byte stream in base 256
 * @param int $base either 10 or 256
 * @return resource a bignum
 */
function bignum_new($str, $base = 10) {
    if ($base == 10) {
        if (BIGNUM_GMP) {
            return gmp_init($str, 10);
        } else {
            return $str;
        }
    } elseif ($base == 256) {
        $bytes = array_merge(unpack('C*', $str));

        $num = bignum_new(0);
  
        foreach ($bytes as $byte) {
            $num = bignum_mul($num, 256);
            $num = bignum_add($num, bignum_new($byte));
        }
        return $num;
    }
    return FALSE;
}

/**
 * Converts a bignum into a string representation (base 10) or a byte stream
 * (base 256)
 *
 * @param resource $num the bignum
 * @param int $base either 10 or 256
 * @return string the converted bignum
 */
function bignum_val($num, $base = 10) {
    if (BIGNUM_GMP) {
        $base10 = gmp_strval($num, 10);
    } else {
        $base10 = $num;
    }

    if ($base == 10) return $base10;
    if ($base == 256) {
        $cmp = bignum_cmp($num, 0);
        if ($cmp < 0) {
            return FALSE;
        }
    
        if ($cmp == 0) {
            return "\x00";
        }
    
        $bytes = array();
      
        while (bignum_cmp($num, 0) > 0) {
            array_unshift($bytes, bignum_mod($num, 256));
            $num = bignum_div($num, 256);
        }
      
        if ($bytes && ($bytes[0] > 127)) {
            array_unshift($bytes, 0);
        }
      
        $byte_stream = '';
        foreach ($bytes as $byte) {
            $byte_stream .= pack('C', $byte);
        }
      
        return $byte_stream;
    }
    return FALSE;
}

/**
 * Adds two bignums
 *
 * @param resource $a
 * @param resource $b
 * @return resource a bignum representing a + b
 */
function bignum_add($a, $b) {
    if (BIGNUM_GMP) {
        return gmp_add($a, $b);
    } else {
        return bcadd($a, $b);
    }
}

/**
 * Multiplies two bignums
 *
 * @param resource $a
 * @param resource $b
 * @return resource a bignum representing a * b
 */
function bignum_mul($a, $b) {
    if (BIGNUM_GMP) {
        return gmp_mul($a, $b);
    } else {
        return bcmul($a, $b);
    }
}

/**
 * Divides two bignums
 *
 * @param resource $a
 * @param resource $b
 * @return resource a bignum representing a / b
 */
function bignum_div($a, $b) {
    if (BIGNUM_GMP) {
        return gmp_div($a, $b);
    } else {
        return bcdiv($a, $b);
    }
}

/**
 * Raise base to power exp
 *
 * @param resource $base the base
 * @param mixed $exp the exponent, as an integer or a bignum
 * @return resource a bignum representing base ^ exp
 */
function bignum_pow($base, $exp) {
    if (BIGNUM_GMP) {
        if (is_resource($exp) && (get_resource_type($exp) == 'gmp')) $exp = gmp_intval($exp);
        return gmp_pow($base, $exp);
    } else {
        return bcpow($base, $exp);
    }
}

/**
 * Returns n modulo d
 *
 * @param resource $n
 * @param resource $d
 * @return resource a bignum representing n mod d
 */
function bignum_mod($n, $d) {
    if (BIGNUM_GMP) {
        return gmp_mod($n, $d);
    } else {
        return bcmod($n, $d);
    }
}

/**
 * Raise a number into power with modulo
 *
 * @param resource $base the base
 * @param resource $exp the exponent
 * @param resource $mod the modulo
 * @return resource a bignum representing base ^ exp mod mod
 */
function bignum_powmod($base, $exp, $mod) {
    if (BIGNUM_GMP) {
        return gmp_powm($base, $exp, $mod);
    } elseif (function_exists('bcpowmod')) {
        return bcpowmod($base, $exp, $mod);
    } else {
        $square = bignum_mod($base, $mod);
        $result = 1;
        while (bignum_cmp($exp, 0) > 0) {
            if (bignum_mod($exp, 2)) {
                $result = bignum_mod(bignum_mul($result, $square), $mod);
            }
            $square = bignum_mod(bignum_mul($square, $square), $mod);
            $exp = bignum_div($exp, 2);
        }
        return $result;
    }
}

/**
 * Compares two bignum
 *
 * @param resource $a
 * @param resource $b
 * @return int positive value if a > b, zero if a = b and a negative value if a < b
 */
function bignum_cmp($a, $b) {
    if (BIGNUM_GMP) {
        return gmp_cmp($a, $b);
    } else {
        return bccomp($a, $b);
    }
}
?>
