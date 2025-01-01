<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2009-2024
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
    /** @var \GMP|string the internal representation of the value */
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
            case 256:
                $unpacked = unpack('C*', $str);
                assert($unpacked != false);
                $bytes = array_merge($unpacked);

                $value = (new BigNum(0))->value;
          
                foreach ($bytes as $byte) {
                    $value = $this->_mul($value, 256);
                    $value = $this->_add($value, (new BigNum($byte))->value);
                }
                $this->value = $value;
                return;
            default:
                if (!is_integer($base) || ($base < 2) || ($base > 36))
                    throw new \InvalidArgumentException('Invalid base');

                $value = (new BigNum(0))->value;

                for ($i = 0; $i < strlen($str); $i++) {
                    $value = $this->_mul($value, $base);
                    $value = $this->_add($value, (new BigNum(base_convert($str[$i], $base, 10)))->value);
                }
                $this->value = $value;
                return;
        }
    }

    /**
     * Converts a bignum into a string representation (base 2 to 36) or a byte stream
     * (base 256)
     *
     * @param int $base an integer between 2 and 36, or 256
     * @return string|false the converted bignum
     */
    function val($base = 10) {
        switch ($base) {
            case 10:
                if (BIGNUM_GMP) {
                    $base10 = gmp_strval($this->value, 10);
                } else {
                    /** @var string $base10 */
                    $base10 = $this->value;
                }

                return $base10;
        
            case 256:
                $cmp = $this->_cmp($this->value, 0);
                if ($cmp < 0) {
                    return FALSE;
                }
        
                if ($cmp == 0) {
                    return "\x00";
                }
        
                $bytes = [];
                $num = $this->value;
          
                while ($this->_cmp($num, 0) > 0) {
                    $x = $this->_mod($num, 256);
                    if ($x instanceof \GMP) $x = gmp_intval($x);
                    array_unshift($bytes, (int) $x);
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
                        $i = gmp_intval($r);
                    } else {
                        /** @var string $r */
                        $i = intval($r);
                    }
                    $str = base_convert(strval($i), 10, $base) . $str;
                    $num = $this->_div($num, $base);
                }
     
                return $str;
        }
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
     * @param int $exp the exponent
     * @return BigNum a bignum representing this ^ exp
     */
    function pow($exp) {
        $result = new BigNum(0);
        $result->value = $this->_pow($this->value, $exp);
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
        $val = $this->val();
        return ($val) ? $val : 'NaN';
    }

    /**
     * Adds two bignums
     *
     * @param \GMP|string $a
     * @param \GMP|string $b
     * @return \GMP|string a bignum representing a + b
     */
    protected function _add($a, $b) {
        if (BIGNUM_GMP) {
            return gmp_add($a, $b);
        } else {
            /** @var numeric-string $a */
            /** @var numeric-string $b */
            return bcadd($a, $b);
        }
    }

    /**
     * Multiplies two bignums
     *
     * @param \GMP|int|string $a
     * @param \GMP|int|string $b
     * @return \GMP|string a bignum representing a * b
     */
    protected function _mul($a, $b) {
        if (BIGNUM_GMP) {
            return gmp_mul($a, $b);
        } else {
            /** @var numeric-string $a */
            /** @var numeric-string $b */
            return bcmul($a, $b);
        }
    }

    /**
     * Divides two bignums
     *
     * @param \GMP|int|string $a
     * @param \GMP|int|string $b
     * @return \GMP|string a bignum representing a / b
     */
    protected function _div($a, $b) {
        if (BIGNUM_GMP) {
            return gmp_div($a, $b);
        } else {
            /** @var string $a */
            /** @var string $b */
            return bcdiv($a, $b);
        }
    }

    /**
     * Raise base to power exp
     *
     * @param \GMP|string $base the base
     * @param int|string $exp the exponent, as an integer or a bignum
     * @return \GMP|string a bignum representing base ^ exp
     */
    function _pow($base, $exp) {
        if (BIGNUM_GMP) {
            return gmp_pow($base, intval($exp));
        } else {
            /** @var numeric-string $base */
            /** @var numeric-string $exp */
            $exp = strval($exp);
            return bcpow($base, $exp);
        }
    }

    /**
     * Returns n modulo d
     *
     * @param \GMP|int|string $n
     * @param \GMP|int|string $d
     * @return \GMP|string a bignum representing n mod d
     */
    protected function _mod($n, $d) {
        if (BIGNUM_GMP) {
            return gmp_mod($n, $d);
        } else {
            /** @var string $n */
            /** @var string $d */
            return bcmod($n, $d);
        }
    }

    /**
     * Raise a number into power with modulo
     *
     * @param \GMP|string $base the base
     * @param \GMP|string $exp the exponent
     * @param \GMP|string $mod the modulo
     * @return \GMP|string|null a bignum representing base ^ exp mod mod
     */
    protected function _powmod($base, $exp, $mod) {
        if (BIGNUM_GMP) {
            return gmp_powm($base, $exp, $mod);
        } elseif (function_exists('bcpowmod')) {
            /** @var string $base */
            /** @var string $exp */
            /** @var string $mod */
            $result = bcpowmod($base, $exp, $mod);
            if ($result == false) return null;
            return $result;
        } else {
            $square = $this->_mod($base, $mod);
            $result = '1';
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
     * @param \GMP|int|string $a
     * @param \GMP|int|string $b
     * @return int positive value if a > b, zero if a = b and a negative value if a < b
     */
    protected function _cmp($a, $b) {
        if (BIGNUM_GMP) {
            return gmp_cmp($a, $b);
        } else {
            /** @var numeric-string $a */
            /** @var numeric-string $b */
            return bccomp($a, $b);
        }
    }
}

?>
