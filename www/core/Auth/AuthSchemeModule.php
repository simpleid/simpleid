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

namespace SimpleID\Auth;

use SimpleID\Module;
use SimpleID\ModuleManager;

/**
 * An abstract authentication scheme module.
 *
 * This module contains convenience variables, `$auth`
 * and `$mgr`, pointing to instances of
 * `AuthManager` and `ModuleManager`
 * respectively
 */
abstract class AuthSchemeModule extends Module {

    /** @var AuthManager */
    protected $auth;

    /** @var SimpleID\ModuleManager */
    protected $mgr;

    public function __construct() {
        parent::__construct();
        $this->auth = AuthManager::instance();
        $this->mgr = ModuleManager::instance();
    }
}
?>