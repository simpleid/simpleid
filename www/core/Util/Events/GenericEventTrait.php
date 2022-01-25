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

namespace SimpleID\Util\Events;

/**
 * A utility trait for implementing {@link \GenericEventInterface}.
 */
trait GenericEventTrait {
    /** @var string */
    protected $eventName;

    /**
     * Creates a data collection event
     * 
     * @param string $eventName the name of the event, or the name of the
     * class if null
     */
    protected function setEventName($eventName = null) {
        if ($eventName == null) {
            // We use static::class instead of self::class or __CLASS__
            // to pick up the name of the subclass instead of
            // BaseDataCollectionEvent (if applicable)
            $this->eventName = static::class;
        } else {
            $this->eventName = $eventName;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getEventName() {
        return $this->eventName;
    }
}

?>