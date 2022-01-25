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
 * A utility trait for implementing {@link Psr\EventDispatcher\StoppableEventInterface}.
 */
trait StoppableEventTrait {
    protected $stopped = false;

    /**
     * @see Psr\EventDispatcher\StoppableEventInterface::isPropagationStopped()
     */
    public function isPropagationStopped(): bool {
        return $this->stopped;
    }

    /**
     * Stops further propagation of the event
     */
    public function stopPropagation() {
        $this->stopped = true;
        return $this;
    }
}

?>