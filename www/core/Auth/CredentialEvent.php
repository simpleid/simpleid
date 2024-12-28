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

use \GenericEventInterface;
use SimpleID\Models\User;
use SimpleID\Base\AuditEvent;
use SimpleID\Util\Events\GenericEventTrait;

/**
 * Event dispatched when a user has added, changed or removed a credential under
 * an authentication scheme.
 * 
 * Some authentication schemes handle multiple credentials (e.g. WebAuthnAuthSchemeModule
 * handles multiple security keys), whereas others can only handle a single
 * credential (e.g. a password).  If an authentication scheme handle multiple credentials,
 * each credential is identified using a module-specifc ID.
 */
class CredentialEvent extends AuditEvent implements GenericEventInterface {
    use GenericEventTrait;

    /** Event type when a credential is added to the user's profile */
    const CREDENTIAL_ADDED_EVENT = 'credential_added';

    /** Event type when a credential is changed in the user's profile (e.g. changing a password) */
    const CREDENTIAL_CHANGED_EVENT = 'credential_changed';

    /** Event type when a credential is deleted from the user's profile */
    const CREDENTIAL_DELETED_EVENT = 'credential_deleted';

    /** @var string $authModuleName */
    protected $authModuleName;

    /** @var ?string $credentialId */
    protected $credentialId;

    /**
     * Creates a credential event.
     * 
     * @param User $user the user whose credentials were affected by this event
     * @param string $event_type the event type (one of `CREDENTIAL_ADDED_EVENT`,
     * `CREDENTIAL_CHANGED_EVENT` or `CREDENTIAL_DELETED_EVENT`)
     * @param string $auth_module_name the name of the module which is managing
     * the credential
     * @param ?string $credential_id the module-specifc ID of the credential (if any)
     */
    public function __construct(User $user, string $event_type, string $auth_module_name, string $credential_id = null) {
        parent::__construct($user);
        $this->setEventName($event_type);
        $this->authModuleName = $auth_module_name;
        $this->credentialId = $credential_id;
    }

    /**
     * Returns the name of the module that manages this credential.
     * 
     * @return string the fully qualified class name of the module
     * that manages this credential
     */
    public function getAuthModuleName(): string {
        return $this->authModuleName;
    }

    /**
     * Returns the ID of the credential affected by this event.
     * 
     * If the authentication scheme only handles one credential, this function
     * may return null.
     * 
     * @return string ID of the credential affected by this event
     */
    public function getCredentialId(): ?string {
        return $this->credentialId;
    }
}

?>