<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021
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

namespace SimpleID\Util\Forms;

use SimpleID\Util\ArrayWrapper;

/**
 * A wrapper around an array used to store the state of a form.
 * 
 * Form states are typically serialised through
 * {@link SimpleID\Util\SecurityToken} and then passed around
 */
class FormState extends ArrayWrapper {

    public const REQUEST_KEY = 'rq';
    public const RESPONSE_KEY = 'rs';

    public function __construct($data = []) {
        if (!is_array($data)) $data = [];
        parent::__construct($data);
    }


    public function setRequest(ArrayWrapper $request) {
        $this->offsetSet(self::REQUEST_KEY, $request);
    }

    public function getRequestArray() {
        return $this->offsetGet(self::REQUEST_KEY);
    }


    public function setResponse(ArrayWrapper $response) {
        $this->offsetSet(self::RESPONSE_KEY, $response);
    }

    public function getResponseArray() {
        return $this->offsetGet(self::RESPONSE_KEY);
    }

}

?>