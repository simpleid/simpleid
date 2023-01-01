<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2023
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
 * Dot-notation can be used in {@link pathGet()}, {@link pathExists()}, {@link pathSet()},
 * and {@link pathRef()}.  Thus in the example above:
 *
 * <code>
 * $array_wrapper = new ArrayWrapper(['dim1' => ['foo' => 1, 'bar' => 2]]);
 * print $array_wrapper->pathGet('dim1.foo');  # Prints 1
 * $array_wrapper->pathSet('dim.foo', 3);      # Works!
 * print $array_wrapper->pathGet('dim1.foo');  # Now prints 3
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
     */
    public function offsetGet($offset) {
        return isset($this->container[$offset]) ? $this->container[$offset] : null;
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
     */
    public function pathGet($path) {
        $value = $this->pathRef($path);
        return $value;
    }

    /**
     * Determines whether a FatFree-like path
     * expression can be resolved
     *
     * @param string $path the path
     * @return bool true if the path can be resolved
     */
    public function pathExists($path) {
        $value = $this->pathRef($path, false);
        return isset($value);
    }

    /**
     * Sets the value of the element specified by a FatFree-like path
     * expression
     *
     * @param string $path the path
     * @param mixed $value the value to set
     * @return void
     */
    public function pathSet($path, $value) {
        $ref = &$this->pathRef($path);
        $ref = $value;
    }

    /**
     * Removes the element specified by a FatFree-like path
     * expression
     *
     * @param string $path the path
     * @return void
     */
    public function pathUnset($path) {
        if (!$this->pathExists($path)) return;

        $parts = $this->pathSplit($path);

        if (count($parts) == 1) {
            unset($this->container[$path]);
            return;
        }

        $key = array_pop($parts);
        if (array_pop($parts) == '->') {
            $ref = &$this->pathRefLimit($path, true, 2);
            unset($ref->$key);
        } else {
            $ref = &$this->pathRefLimit($path, true, 1);
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
     * @param string $path the path
     * @param bool $add adds non-existent keys, array elements, and object properties
     * @return mixed the contents of the container matching the path
     */
    public function &pathRef($path, $add = TRUE) {
        return $this->pathRefLimit($path, $add);
    }

    /**
     * Retrieve contents of the container based on a FatFree-like path
     * expression, as a reference.
     *
     * If $add is set to true, adds non-existent keys,
     * array elements, and object properties
     *
     * @param string $path the path
     * @param bool $add adds non-existent keys, array elements, and object properties
     * @param int|null $limit the number of path elements to traverse, or null for
     * unlimited
     * @return mixed the contents of the container matching the path
     */
    protected function &pathRefLimit($path, $add = TRUE, $limit = NULL) {
        $null = NULL;

        $parts = $this->pathSplit($path);
        if ($limit != null) $parts = array_slice($parts, 0, -$limit);

        if (!preg_match('/^\w+$/', $parts[0])) return null;

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
     * @param string $path
     * @return array<string>
     */
    private function pathSplit($path) {
        $split = preg_split('/\[\h*[\'"]?(.+?)[\'"]?\h*\]|(->)|\./', $path, -1, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
        if ($split === false) {
            return [ $path ];
        } else {
            return $split;
        }
    }
}
?>