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

namespace SimpleID\Util\Events;

/**
 * A utility trait for implementing {@link \GenericEventInterface}.
 * 
 * @see https://github.com/kelvinmo/f3-event-dispatcher
 */
trait GenericEventTrait {
    /** @var string */
    protected $eventName;

    /**
     * Sets the name of the event to be returned by `GenericEventInterface::getEventName()`.
     * 
     * The name of the event is specified by the `$eventName` parameter.  If
     * `$eventName` is null, then the name of the class which inserted the trait
     * is used instead.
     * 
     * @param string $eventName the name of the event, or null
     * @return void
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
     * @see \GenericEventInterface::getEventName()
     * 
     * @return string
     */
    public function getEventName() {
        if ($this->eventName == null) {
            return static::class;
        } else {
            return $this->eventName;
        }
    }
}

?>
