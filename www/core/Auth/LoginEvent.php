<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2025
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

use SimpleID\Base\AuditEvent;
use SimpleID\Util\Forms\FormEventInterface;

/**
 * Event to log in a user.
 * 
 * This event is dispatched when all the authentication components are
 * completed. Listeners can use this hook to save any authentication
 * information.
 *
 * The state of the login form (if any) used in the process can be
 * obtained from the {@link getFormState()} method.  It contains the same
 * elements as per the `login_form_build` event.
 * 
 * This event also provides further information on the authentication
 * result via the {@link getAuthResult()} method.  Convenience
 * methods {@link getUser()} and {@link getAuthLevel()} are also
 * included.
 */
class LoginEvent extends AuditEvent implements FormEventInterface {
    /** @var AuthResultInterface */
    protected $result;

    /** @var \SimpleID\Util\Forms\FormState|null */
    protected $form_state = null;

    /**
     * @param AuthResultInterface $result
     * @param \SimpleID\Util\Forms\FormState|null $form_state
     */
    public function __construct(AuthResultInterface $result, $form_state = null) {
        parent::__construct($result->getUser());
        $this->result = $result;
        $this->form_state = $form_state;
    }

    /**
     * Returns the underlying successful authentication result.
     * 
     * @return AuthResultInterface the authentication result
     */
    public function getAuthResult() {
        return $this->result;
    }

    /**
     * {@inheritdoc}
     */
    public function getFormState() {
        return $this->form_state;
    }

    /**
     * Returns the user to be logged in.
     * 
     * This is a proxy for `getAuthResult()->getUser()`.
     * 
     * @return \SimpleID\Models\User the user
     */
    public function getUser() {
        return $this->result->getUser();
    }

    /**
     * Returns the level of authentication achieved in this
     * session.
     * 
     * This is a proxy for `getAuthResult()->getAuthLevel()`.
     * 
     * @return int the authentication level
     */
    public function getAuthLevel() {
        return $this->result->getAuthLevel();
    }
}

?>