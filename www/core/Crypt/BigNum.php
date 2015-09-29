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
 */

/**
 * Abstraction library for multiple precision mathematics.  This file uses either
 * the GNU Multiple Precision Arithmic Libary (GMP) if it is installed, or the
 * default BCMath library if it is not installed.
 *
 * @package simpleid
 * @filesource
 */

namespace SimpleID\Crypt;
 
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
 * A generic big integer using the GMP or the BCMath library.
 */
class BigNum {
    /** @var resource the internal representation of the value */
    protected $value;

    /**
     * Returns whether either the GMP or the BCMath library is installed.  If neither
     * of these libraries are installed, the functions in this file will not work.
     *
     * @return bool true if either GMP or BCMath is installed.
     */ 
    static function loaded() {
        return (function_exists('gmp_init') || function_exists('bcadd'));
    }

    /**
     * Creates a bignum.
     *
     * @param mixed $str An integer, a string in base 2 to 36, or a byte stream in base 256
     * @param int $base an integer between 2 and 36, or 256
     * @return resource a bignum
     */
    public function __construct($str, $base = 10) {
        switch ($base) {
            case 10:
                if (BIGNUM_GMP) {
                    $this->value = gmp_init($str, 10);
                } else {
                    $this->value = $str;
                }
                return;
                break;
            case 256:
                $bytes = array_merge(unpack('C*', $str));

                $value = (new BigNum(0))->value;
          
                foreach ($bytes as $byte) {
                    $value = $this->_mul($value, 256);
                    $value = $this->_add($value, (new BigNum($byte))->value);
                }
                $this->value = $value;
                return;
                break;
            default:
                if (!is_integer($base) || ($base < 2) || ($base > 36)) return FALSE;

                $value = (new BigNum(0))->value;

                for ($i = 0; $i < strlen($str); $i++) {
                    $value = $this->_mul($value, $base);
                    $value = $this->_add($value, (new BigNum(base_convert($str[$i], $base, 10)))->value);
                }
                $this->value = $value;
                return;
        }

        throw new \RuntimeException();
    }

    /**
     * Converts a bignum into a string representation (base 2 to 36) or a byte stream
     * (base 256)
     *
     * @param int $base an integer between 2 and 36, or 256
     * @return string the converted bignum
     */
    function val($base = 10) {
        switch ($base) {
            case 10:
                if (BIGNUM_GMP) {
                    $base10 = gmp_strval($this->value, 10);
                } else {
                    $base10 = $this->value;
                }

                return $base10;
                break;
        
            case 256:
                $cmp = $this->_cmp($this->value, 0);
                if ($cmp < 0) {
                    return FALSE;
                }
        
                if ($cmp == 0) {
                    return "\x00";
                }
        
                $bytes = array();
                $num = $this->value;
          
                while ($this->_cmp($num, 0) > 0) {
                    array_unshift($bytes, $this->_mod($num, 256));
                    $num = $this->_div($num, 256);
                }
          
                if ($bytes && ($bytes[0] > 127)) {
                    array_unshift($bytes, 0);
                }
          
                $byte_stream = '';
                foreach ($bytes as $byte) {
                    $byte_stream .= pack('C', $byte);
                }
          
                return $byte_stream;
                break;
            default:
                if (!is_integer($base) || ($base < 2) || ($base > 36)) return FALSE;

                $cmp = $this->_cmp($this->value, 0);
                if ($cmp < 0) {
                    return FALSE;
                }
        
                if ($cmp == 0) {
                    return "0";
                }

                $str = '';
                $num = $this->value;

                while ($this->_cmp($num, 0) > 0) {
                    $r = $this->_mod($num, $base);
                    if (BIGNUM_GMP) {
                        $r = gmp_intval($r);
                    } else {
                        $r = intval($r);
                    }
                    $str = base_convert($r, 10, $base) . $str;
                    $num = $this->_div($num, $base);
                }
     
                return $str;
        }
        
        return FALSE;
    }

    /**
     * Adds two bignums
     *
     * @param BigNum $b
     * @return BigNum a bignum representing this + b
     */
    function add($b) {
        $result = new BigNum(0);
        $result->value = $this->_add($this->value, $b->value);
        return $result;
    }

    /**
     * Multiplies two bignums
     *
     * @param BigNum $b
     * @return BigNum a bignum representing this * b
     */
    function mul($b) {
        $result = new BigNum(0);
        $result->value = $this->_mul($this->value, $b->value);
        return $result;
    }

    /**
     * Raise base to power exp
     *
     * @param BigNum $exp the exponent
     * @return BigNum a bignum representing this ^ exp
     */
    function pow($exp) {
        $result = new BigNum(0);
        $result->value = $this->_mul($this->value, $exp->value);
        return $result;
    }

    /**
     * Divides two bignums
     *
     * @param BigNum $b
     * @return BigNum a bignum representing this / b
     */
    function div($b) {
        $result = new BigNum(0);
        $result->value = $this->_div($this->value, $b->value);
        return $result;
    }

    /**
     * Returns n modulo d
     *
     * @param BigNum $d
     * @return BigNum a bignum representing this mod d
     */
    function mod($d) {
        $result = new BigNum(0);
        $result->value = $this->_mod($this->value, $d->value);
        return $result;
    }

    /**
     * Raise a number into power with modulo
     *
     * @param BigNum $exp the exponent
     * @param BigNum $mod the modulo
     * @return BigNum a bignum representing this ^ exp mod mod
     */
    function powmod($exp, $mod) {
        $result = new BigNum(0);
        $result->value = $this->_powmod($this->value, $exp->value, $mod->value);
        return $result;
    }

    /**
     * Compares two bignum
     *
     * @param BigNum $b
     * @return int positive value if this > b, zero if this = b and a negative value if this < b
     */
    function cmp($b) {
        return $this->_cmp($this->value, $b->value);
    }

    /**
     * Returns a string representation.
     *
     * @return string
     */
    function __toString() {
        return $this->val();
    }

    /**
     * Adds two bignums
     *
     * @param resource $a
     * @param resource $b
     * @return resource a bignum representing a + b
     */
    protected function _add($a, $b) {
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
    protected function _mul($a, $b) {
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
    protected function _div($a, $b) {
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
    function _pow($base, $exp) {
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
    protected function _mod($n, $d) {
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
    protected function _powmod($base, $exp, $mod) {
        if (BIGNUM_GMP) {
            return gmp_powm($base, $exp, $mod);
        } elseif (function_exists('bcpowmod')) {
            return bcpowmod($base, $exp, $mod);
        } else {
            $square = $this->_mod($base, $mod);
            $result = 1;
            while ($this->_cmp($exp, 0) > 0) {
                if ($this->_mod($exp, 2)) {
                    $result = $this->_mod($this->_mul($result, $square), $mod);
                }
                $square = $this->_mod($this->_mul($square, $square), $mod);
                $exp = $this->_div($exp, 2);
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
    protected function _cmp($a, $b) {
        if (BIGNUM_GMP) {
            return gmp_cmp($a, $b);
        } else {
            return bccomp($a, $b);
        }
    }
}

?>
