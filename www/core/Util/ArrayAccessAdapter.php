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

namespace SimpleID\Util;

use \ArrayAccess;

/**
 * An abstract class implementing the ArrayAccess interface
 */
class ArrayAccessAdapter implements ArrayAccess {

    protected $container = array();

    /**
     * Returns this object as an array.
     *
     * @return array
     */
    public function toArray() {
        return $this->container;
    }

    /**
     * Implementation of ArrayAccess
     */
    public function offsetSet($offset, $value) {
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    /**
     * Implementation of ArrayAccess
     */
    public function offsetExists($offset) {
        return isset($this->container[$offset]);
    }

    /**
     * Implementation of ArrayAccess
     */
    public function offsetUnset($offset) {
        unset($this->container[$offset]);
    }

    /**
     * Implementation of ArrayAccess
     */
    public function offsetGet($offset) {
        return isset($this->container[$offset]) ? $this->container[$offset] : null;
    }
}
?>