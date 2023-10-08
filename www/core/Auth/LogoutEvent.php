<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2023
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
use SimpleID\Base\AuditEvent;

/**
 * Event to log out a user.
 * 
 * Listeners can use this event to clean up any saved information when a user
 * logs out.
 * 
 * The user being logged out can be obtained from the {@link getUser()}
 * method.
 * 
 */
class LogoutEvent extends AuditEvent {
    public function __construct(User $user) {
        parent::__construct($user);
    }

    /**
     * Returns the user being logged out.
     * 
     * @return User the user
     */
    public function getUser(): User {
        /** @var User */
        $user = $this->subject;
        return $user;
    }
}

?>