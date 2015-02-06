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

namespace SimpleID\Store;

use SimpleID\Module;

abstract class StoreModule extends Module {
    public function __construct() {
        parent::__construct();
        $store_manager = StoreManager::instance();
        $store_manager->addStore($this, $this->getStores());
    }

    abstract public function getStores();

    abstract public function find($type, $criteria, $value);

    abstract public function read($type, $id);

    abstract public function write($type, $id, $value);

    abstract public function delete($type, $id);

    abstract public function exists($type, $id);
}

?>