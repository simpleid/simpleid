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

namespace SimpleID\Base;

use Psr\EventDispatcher\StoppableEventInterface;
use SimpleID\Util\Events\BaseEvent;
use SimpleID\Util\Events\StoppableEventTrait;

/**
 * An event requesting processing of the root route (i.e. `/`).
 * 
 * The request to be processed can be obtained from the
 * {@link getRequest()} method.  If the listener is able to process
 * the request, it should call the {@link stopPropagation()}
 * method to stop further processing.
 */
class IndexEvent extends BaseEvent implements StoppableEventInterface {
    use StoppableEventTrait;

    /** @var array<string, mixed> */
    protected $request;

    /**
     * @param array<string, mixed> $request
     */
    public function __construct($request) {
        $this->request = $request;
    }

    /** @return array<string, mixed> */
    public function getRequest() {
        return $this->request;
    }
}

?>