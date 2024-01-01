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

use Psr\EventDispatcher\StoppableEventInterface;
use SimpleID\Models\User;

/**
 * An interface for classes that can return an authentication result.
 * 
 */
interface AuthResultInterface extends StoppableEventInterface {
    /**
     * Returns whether the authentication result was successful.
     * 
     * If the result was successful, the authentication parameters can
     * be obtained through other methods in this interface
     * 
     * @return bool true if authentication was successful
     */
    public function isAuthSuccessful();

    /**
     * Returns the authenticated user
     * 
     * @return User the user, or null if no users can
     * be authenticated
     */
    public function getUser(): ?User;

    /**
     * Returns the level of authentication achieved in this
     * session
     * 
     * @return int the authentication level
     */
    public function getAuthLevel();

    /**
     * Returns the name of the modules that used to
     * authenticate the user in this session.
     * 
     * @return array<string> an array of fully qualified class names of the modules
     * involved in the authentication process
     */
    public function getAuthModuleNames();
}

?>