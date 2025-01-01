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

namespace SimpleID\Base;

use SimpleID\Models\User;
use SimpleID\Util\Events\GenericEventTrait;

/**
 * Event where a change has occurred to a user consent.
 * 
 * The `$eventName` can be one of the following:
 * 
 * - `consent_revoke`
 */
class ConsentEvent extends AuditEvent implements \GenericEventInterface {
    use GenericEventTrait;

    /** @var string */
    protected $cid;

    /** @var array<string, mixed> */
    protected $prefs;

    /**
     * @param string $eventName
     * @param User $user
     * @param string $cid
     * @param array<string, mixed> $prefs
     */
    public function __construct($eventName, $user, $cid, $prefs) {
        parent::__construct($user);

        $this->setEventName($eventName);
        $this->cid = $cid;
        $this->prefs = $prefs;
    }

    /**
     * @return string
     */
    public function getConsentID() {
        return $this->cid;
    }

    /**
     * @return array<string, mixed>
     */
    public function getUserPrefs() {
        return $this->prefs;
    }
}

?>