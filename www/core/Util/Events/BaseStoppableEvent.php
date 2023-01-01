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

namespace SimpleID\Util\Events;

use Psr\EventDispatcher\StoppableEventInterface;

/**
 * A generic event that can be stopped.
 */
class BaseStoppableEvent implements \GenericEventInterface, StoppableEventInterface {
    use GenericEventTrait;
    use StoppableEventTrait;

    /**
     * Creates a stoppable event.
     * 
     * @param string $eventName the name of the event
     */
    public function __construct($eventName = null) {
        $this->setEventName($eventName);
    }
}

?>