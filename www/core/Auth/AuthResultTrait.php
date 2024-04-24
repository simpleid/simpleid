<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2024
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

use SimpleID\Models\User;

/**
 * A utility trait providing base functionality to implement
 * {@link AuthResultInterface}
 * 
 */
trait AuthResultTrait {
    /** @var User|null */
    protected $user = null;

    /** @var int */
    protected $auth_level = AuthManager::AUTH_LEVEL_SESSION;

    /** @var array<string> */
    protected $auth_module_names = [];

    /** @var array<string|int> */
    protected $acr = [];

    /**
     * Returns the authenticated user
     * 
     * @return User the user
     */
    public function getUser(): ?User {
        return $this->user;
    }

    /**
     * Returns the level of authentication achieved in this
     * session
     * 
     * @see AuthResultInterface::getAuthLevel()
     */
    public function getAuthLevel(): int {
        return $this->auth_level;
    }

    /**
     * Returns the authentication context class references in relation
     * to the current authentication session.
     *
     * @see AuthResultInterface::getACR()
     */
    public function getACR(): array {
        return $this->acr;
    }

    /**
     * Returns the name of the modules that authenticated user.
     * 
     * @return array<string> the name of the modules
     */
    public function getAuthModuleNames(): array {
        return array_unique($this->auth_module_names);
    }
}
