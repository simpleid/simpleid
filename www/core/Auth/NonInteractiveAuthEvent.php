<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2024
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
use SimpleID\Util\Events\BaseEvent;

/**
 * Event to attempt to login non-interactively using credentials presented
 * by the user agent.
 *
 * This event is created by the {@link SimpleID\Auth\AuthManager::initUser()}
 * function. Listeners should detect any credentials present in the request
 * call the {@link setUser()} method if credentials identifying the user is present.
 *
 * This event is stopped once a user has been set.
 * 
 */
class NonInteractiveAuthEvent extends BaseEvent implements AuthResultInterface {
    use AuthResultTrait;

    /**
     * Creates a non-interactive authentication event
     */
    public function __construct() {
        $this->auth_level = AuthManager::AUTH_LEVEL_TOKEN;
    }

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
     * @return void
     */
    public function setUser(User $user, string $auth_module_name) {
        $this->user = $user;
        $this->auth_module_names[] = $auth_module_name;
    }

    /**
     * Sets the authentication level
     * 
     * @param int $auth_level the authentication level
     * @return void
     */
    public function setAuthLevel(int $auth_level) {
        if ($auth_level > AuthManager::AUTH_LEVEL_NON_INTERACTIVE)
            throw new \InvalidArgumentException('Cannot set authentication level higher than AUTH_LEVEL_NON_INTERACTIVE');
        $this->auth_level = max($auth_level, $this->auth_level);
    }

    /**
     * {@inheritdoc}
     */
    public function isPropagationStopped(): bool {
        return $this->isAuthSuccessful();
    }
}

?>