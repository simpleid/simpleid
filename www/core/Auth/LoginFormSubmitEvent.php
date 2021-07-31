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

namespace SimpleID\Auth;

use SimpleID\Models\User;
use SimpleID\Util\Forms\FormSubmitEvent;

/**
 * An event used to process the login form.
 * 
 */
class LoginFormSubmitEvent extends FormSubmitEvent implements AuthResultInterface {
    protected $user = null;
    protected $auth_level = 0;
    protected $auth_module_names = [];

    /**
     * Creates a form submission event
     * 
     * @param SimpleID\Util\Forms\FormState $form_state a reference to the form state array
     * @param string $eventName the name of the event, or the name
     */
    public function __construct($form_state, $eventName = null) {
        parent::__construct($form_state, $eventName);
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
     * @param SimpleID\Models\User $user the user
     */
    public function setUser(User $user) {
        $this->user = $user;
    }

    /**
     * Returns the authenticated user
     * 
     * @return SimpleID\Models\User the user
     */
    public function getUser(): ?User {
        return $this->user;
    }

    /**
     * Sets the authentication level.
     * 
     * If the authentication level specified in the parameter is less
     * than the level set by previous listeners to this event, it
     * is ignored.
     * 
     * @param int $auth_level the authentication level
     */
    public function setAuthLevel($auth_level) {
        $this->auth_level = max($auth_level, $this->auth_level);
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthLevel() {
        return $this->auth_level;
    }

    /**
     * Adds the name of the module that authenticated the user
     * 
     * @param string $auth_module_name the name of the module that
     * authenticated the user
     */
    public function addAuthModuleName($auth_module_name) {
        $this->auth_module_names[] = $auth_module_name;
    }

    /**
     * Returns the name of the modules that authenticated user.
     * 
     * @return string the name of the modules
     */
    public function getAuthModuleNames() {
        return array_unique($this->auth_module_names);
    }
}

?>