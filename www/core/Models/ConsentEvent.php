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

namespace SimpleID\Models;

class ConsentEvent implements \GenericEventInterface {
    /** @var string */
    protected $eventName;

    protected $cid;

    protected $prefs;

    public function __construct($eventName, $cid, $prefs) {
        if ($eventName == null) {
            // We use static::class instead of self::class or __CLASS__
            // to pick up the name of the subclass instead of
            // BaseDataCollectionEvent (if applicable)
            $this->eventName = static::class;
        } else {
            $this->eventName = $eventName;
        }

        $this->cid = $cid;
        $this->prefs = $prefs;
    }

    /**
     * {@inheritdoc}
     */
    public function getEventName() {
        return $this->eventName;
    }


    public function getConsentID() {
        return $this->cid;
    }

    public function getUserPrefs() {
        return $this->prefs;
    }
}

?>