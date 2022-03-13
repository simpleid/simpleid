<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2022
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

namespace SimpleID\Protocols;


/**
 * A utility trait events dealing with assertion results
 * from identity protocols
 */
trait ProtocolResultTrait {
    protected $result = null;

    /**
     * Sets the assertion result.
     * 
     * This method is ignored if the provided assertion result
     * is *not worse* (i.e. greater than) the existing assertion
     * result stored in the event.
     * 
     * The result must be one of the constants defined in
     * {@link SimpleID\Protocols\ProtocolResult}.
     * 
     * @param int $result the assertion result
     */
    public function setResult(int $result) {
        if ($this->result == null) {
            $this->result = $result;
        } else {
            $this->result = min($this->result, $result);
        }
    }

    /**
     * Returns the currently stored assertion result.
     * 
     * If there is no assertion result currently stored
     * (i.e. {@link hasResult()} returns false), this
     * returns {@link SimpleID\Protocols\ProtocolResult::CHECKID_PROTOCOL_ERROR}.
     * 
     * @return int the assertion result
     */
    public function getResult() {
        return ($this->result != null) ? $this->result : self::CHECKID_PROTOCOL_ERROR;
    }

    /**
     * Returns true if an assertion result has been set previously
     * by another listener.
     * 
     * @return bool true if an assertion result has been set previously
     */
    public function hasResult() {
        return ($this->result == null);
    }
}

?>