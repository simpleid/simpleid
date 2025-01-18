<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2025
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

namespace SimpleID\Util;

use \InvalidArgumentException;
use \ArrayAccess;
use \Countable;
use \IteratorAggregate;
use \Traversable;
use \ArrayIterator;

/**
 * A class that wraps around an array while providing array-like and
 * JS-like access notations.  Subclasses of this class are used extensively
 * throughout SimpleID to decorate arrays with additional methods.
 *
 * Two types of access methods are made available with this class.
 *
 * **{@link ArrayAccess} interface.** This class implements the `ArrayAccess`
 * interface.  This means that elements of the underlying array can be
 * accessed directly using PHP's array syntax.
 *
 * It should be noted that when using the ArrayAccess interface, the values
 * returned are *copies* of the values of the underlying array.  This is
 * particularly important if the value itself is an array.  Changes to these
 * lower-dimension values will not be reflected in the original underlying
 * array.  For example, the following will not work.
 *
 * <code>
 * $array_wrapper = new ArrayWrapper(['dim1' => ['foo' => 1, 'bar' => 2]]);
 * print $array_wrapper['dim1']['foo'];  # Prints 1
 * $array_wrapper['dim']['foo'] = 3;     # Will not work
 * print $array_wrapper['dim1']['foo'];  # Still prints 1
 * </code>
 *
 * In order to alter these values in the underlying array, use dot-notation
 * (explained below).
 *
 * **Dot-notation.** Dot notation can be used to traverse through arrays and
 * objects.  Dot notation is similar to JavaScript - use `.` to traverse
 * through arrays (with either string or numeric keys) and `->` to traverse
 * through object properties.  The entire expression in dot-notation is called
 * a *path*.
 * 
 * If a segment in the path contains a dot, this can be escaped using brackets.
 * For example, the expression `a.[b.c].d` is split into `a`, `b.c` and `d`.
 *
 * Dot-notation can be used in {@link get()}, {@link exists()}, {@link set()},
 * and {@link ref()}.  Thus in the example above:
 *
 * <code>
 * $array_wrapper = new ArrayWrapper(['dim1' => ['foo' => 1, 'bar' => 2]]);
 * print $array_wrapper->get('dim1.foo');  # Prints 1
 * $array_wrapper->set('dim.foo', 3);      # Works!
 * print $array_wrapper->get('dim1.foo');  # Now prints 3
 * </code>
 *
 * @implements ArrayAccess<string, mixed>
 * @implements IteratorAggregate<string, mixed>
 */
class ArrayWrapper implements ArrayAccess, Countable, IteratorAggregate {
    /** @var array<mixed> the underlying array */
    protected $container = [];

    /**
     * Creates a new ArrayWrapper over an underlying array
     *
     * @param array<mixed> $container the underlying array
     */
    public function __construct($container = []) {
        if (is_array($container)) $this->container = $container;
    }

    /**
     * Loads data from an array or another ArrayWrapper, replacing existing data.
     *
     * This data is typically read from another source
     *
     * @param array<mixed>|ArrayWrapper $data the data
     * @return void
     */
    public function loadData($data) {
        if ($data instanceof ArrayWrapper) {
            $this->container = array_replace_recursive($this->container, $data->container);
        } elseif (is_array($data)) {
            $this->container = array_replace_recursive($this->container, $data);
        }
    }

    /**
     * Returns this object as an array.
     *
     * @return array<mixed>
     */
    public function toArray() {
        return $this->container;
    }

    /**
     * Implementation of ArrayAccess
     */
    public function offsetSet($offset, $value): void {
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    /**
     * Implementation of ArrayAccess
     */
    public function offsetExists($offset): bool {
        return isset($this->container[$offset]);
    }

    /**
     * Implementation of ArrayAccess
     */
    public function offsetUnset($offset): void {
        unset($this->container[$offset]);
    }

    /**
     * Implementation of ArrayAccess
     * 
     * Ideally we should provide a mixed return type here, but for PHP7 compatibility,
     * we add a ReturnTypeWillChange attribute instead.
     */
    #[\ReturnTypeWillChange]
    public function offsetGet($offset) {
        return isset($this->container[$offset]) ? $this->container[$offset] : null;
    }

    /**
     * Fallback function when attempt to write to non-existing properties.
     * 
     * A fallback function is required to to work around Fat-Free Framework's
     * behaviour when escaping the contents in the hive for template rendering.
     * The Fat-Free code causes a dynamic property to be set, which is
     * deprecated in PHP 8.2.  Having an explicit __set() function allows
     * PHP to call something rather than setting the property dynamically.
     * 
     * This function should not be called by anything other than the Fat-Free
     * Framework.  As a result, the corresponding __get() and __exists() functions
     * are not defined.
     * 
     * @link https://github.com/simpleid/simpleid/pull/132 Further details
     * @link https://www.php.net/manual/en/language.oop5.overloading.php#object.set PHP documention on __set()
     * @deprecated 2.0 This should not be used where possible
     */
    public function __set(string $name, mixed $value): void {
        // Only allow keys already existing in $container to be set
        if (array_key_exists($name, $this->container)) {
            $this->container[$name] = $value;
        } else {
            throw new InvalidArgumentException('Attempt to set a non-existent key');
        }
    }


    /**
     * Implementation of Countable
     */
    public function count(): int {
        return count($this->container);
    }

    /**
     * Implementation of IteratorAggregate
     */
    public function getIterator(): Traversable {
        return new ArrayIterator($this->container);
    }

    /**
     * Retrieve contents of the container based on a FatFree-like path
     * expression
     *
     * @param string $path the path
     * @return mixed the contents of the container matching the path
     * @throws \InvalidArgumentException if $path is empty
     */
    public function get(string $path) {
        $value = $this->ref($path);
        return $value;
    }

    /**
     * Determines whether a FatFree-like path
     * expression can be resolved
     *
     * @param string $path the path
     * @return bool true if the path can be resolved
     * @throws \InvalidArgumentException if $path is empty
     */
    public function exists(string $path) {
        $value = $this->ref($path, false);
        return isset($value);
    }

    /**
     * Sets the value of the element specified by a FatFree-like path
     * expression.
     * 
     * Note that this function will overwrite intermediate parts
     * of the path with array declarations.  For example, the following
     * code:
     * 
     * <code>
     * $wrapper->set('a', 'foo');
     * $wrapper->set('a.b', 'bar');
     * </code>
     * 
     * Will result in `foo` being overwritten.
     *
     * @param string $path the path
     * @param mixed $value the value to set
     * @return void
     * @throws \InvalidArgumentException if $path is empty
     */
    public function set(string $path, $value) {
        $ref = &$this->ref($path);
        $ref = $value;
    }

    /**
     * Appends a value to an array element specified by a FatFree-like path
     * expression.
     *
     * @param string $path the path to the array
     * @param mixed $value the value to append
     * @return void
     * @throws \InvalidArgumentException if $path is empty or does not point
     * to an array
     */
    public function append(string $path, $value) {
        $ref = &$this->ref($path);
        if (is_null($ref)) $ref = [];
        if (!is_array($ref)) throw new \InvalidArgumentException('Not an array: ' . $path);
        $ref[] = $value;
    }

    /**
     * Removes the element specified by a FatFree-like path
     * expression
     *
     * @param string $path the path
     * @return void
     * @throws \InvalidArgumentException if $path is empty
     */
    public function unset(string $path) {
        if (!$this->exists($path)) return;

        $parts = $this->splitPath($path);

        if (count($parts) == 1) {
            unset($this->container[$path]);
            return;
        }

        $key = array_pop($parts);
        if (array_pop($parts) == '->') {
            $ref = &$this->refLimit($path, true, 2);
            unset($ref->$key);
        } else {
            $ref = &$this->refLimit($path, true, 1);
            unset($ref[$key]);
        }
    }

    /**
     * Retrieve contents of the container based on a FatFree-like path
     * expression, as a reference.
     *
     * If $add is set to true, adds non-existent keys,
     * array elements, and object properties
     * 
     * If the path cannot be traversed (for example `a.b.c` but `a.b` is not
     * an array), this function returns null.
     *
     * @param string $path the path
     * @param bool $add adds non-existent keys, array elements, and object properties
     * @return mixed the contents of the container matching the path
     * @throws \InvalidArgumentException if $path is empty
     */
    public function &ref(string $path, bool $add = TRUE) {
        return $this->refLimit($path, $add);
    }

    /**
     * Retrieve contents of the container based on a FatFree-like path
     * expression, as a reference.
     *
     * If $add is set to true, adds non-existent keys,
     * array elements, and object properties.
     * 
     * If the path cannot be traversed (for example `a.b.c` but `a.b` is not
     * an array), this function returns null.
     *
     * @param string $path the path
     * @param bool $add adds non-existent keys, array elements, and object properties
     * @param int|null $limit the number of path elements to traverse, or null for
     * unlimited
     * @return mixed the contents of the container matching the path
     * @throws \InvalidArgumentException if $path is empty
     */
    protected function &refLimit(string $path, bool $add = TRUE, $limit = NULL) {
        $null = NULL;

        $parts = $this->splitPath($path);
        if ($limit != null) $parts = array_slice($parts, 0, -$limit);

        if (!$parts || !preg_match('/^\w+$/', $parts[0])) throw new InvalidArgumentException('$path is empty or invalid');

        if ($add) {
            $var = &$this->container;
        } else {
            $var = $this->container;
        }

        $in_object = FALSE;

        foreach ($parts as $part) {
            if ($part == '->') {
                $in_object = TRUE;
            } elseif ($in_object) {
                $in_object = FALSE;
                if (!is_object($var)) $var = new \stdClass;
                if ($add || property_exists($var, $part)) {
                    $var = &$var->$part;
                } else {
                    $var = &$null;
                    break;
                }
            } else {
                if (!is_array($var)) $var=[];
                if ($add || array_key_exists($part,$var)) {
                    $var = &$var[$part];
                } else {
                    $var = &$null;
                    break;
                }
            }
        }
        return $var;
    }

    /**
     * 
     * 
     * @param string $path
     * @return array<string>
     */
    protected function splitPath(string $path) {
        $split = preg_split('/\[\h*[\'"]?(.+?)[\'"]?\h*\]|(->)|\./', $path, -1, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
        if ($split === false) {
            return [ $path ];
        } else {
            return $split;
        }
    }
}
?>