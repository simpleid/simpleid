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

namespace SimpleID\Auth;

use SimpleID\Models\User;

/**
 * Event to attempt to automatically login using credentials presented
 * by the user agent.
 *
 * This event is created by the {@link SimpleID\Auth\AuthManager::initUser()}
 * function. Listeners should detect any credentials present in the request
 * call the {@link setUser()} method if credentials identifying the user is present.
 *
 * This event is stopped once a user has been set.
 * 
 */
class AutoAuthEvent implements AuthResultInterface {
    protected $user = null;
    protected $auth_module_name = null;

    /**
     * {@inheritdoc}
     */
    public function isAuthSuccessful() {
        return ($this->user != null);
    }

    /**
     * Set the user object for the user that has been automatically
     * authenticated.
     * 
     * @param User $user the user
     * @param string $auth_module_name the name of the module that
     * authenticated the user
     */
    public function setUser(User $user, string $auth_module_name) {
        $this->user = $user;
        $this->auth_module_name = $auth_module_name;
    }

    /**
     * Returns the authenticated user
     * 
     * @return User the user
     */
    public function getUser(): User {
        return $this->user;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthLevel() {
        return AuthManager::AUTH_LEVEL_AUTO;
    }

    /**
     * Returns the name of the module that authenticated user.
     * 
     * @return string the name of the module
     */
    public function getAuthModuleNames() {
        return [ $this->auth_module_name ];
    }

    /**
     * {@inheritdoc}
     */
    public function isPropagationStopped(): bool {
        return $this->isAuthSuccessful();
    }
}

?>