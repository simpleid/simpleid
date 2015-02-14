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

namespace SimpleID\Models;

use SimpleID\Util\ArrayWrapper;
use SimpleID\Store\Storable;

/**
 * A class representing a client.  A client is an application that is
 * requesting to obtain authentication, authorisation or user information
 * from the SimpleID installation.
 *
 * Different protocols may call clients different names.  For example,
 * clients are known as *relying parties* in OpenID 2.
 */
class Client extends ArrayWrapper {

    public $cid;

    protected $dynamic = true;

    public function __construct($data = array()) {
        parent::__construct($data);
    }

    /**
     * Returns whether this client is dynamically registered.
     *
     * A client is *dynamically registered* if it is registered via
     * an API rather than through a client file.
     *
     * @return bool true if the client is dynamically registered
     */
    public function isDynamic() {
        return $this->dynamic;
    }

    /**
     * Returns the plain-text display name for this client.
     *
     * @return string the display name
     */
    public function getDisplayName() {
        return $this->cid;
    }

    /**
     * Returns the HTML display name for this client.
     * Unlike {@link getDisplayName()}, the string returned by this
     * method can have HTML formatting.
     *
     * @return string the display name
     */
    public function getDisplayHTML() {
        return $this->getDisplayName();
    }

    public function getStoreType() {
        return 'client';
    }

    public function getStoreID() {
        return $this->cid;
    }

    public function setStoreID($id) {
        $this->cid = $id;
    }
}

?>