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

namespace SimpleID\Protocols\OAuth;

use SimpleID\Util\Events\GenericEventTrait;
use SimpleID\Util\Events\StoppableEventTrait;
use Psr\EventDispatcher\StoppableEventInterface;

/**
 * A generic event to process an OAuth message.
 * 
 * Events of this kind are triggered whenever some kind of processing
 * is required on an OAuth request.  These include:
 * 
 * - resolving and expanding parameters in the request
 * - validating the request for compliance
 * - determine whether the user has granted access to the request
 * 
 * Listeners can use {@link getRequest()} and {@link getResponse()}
 * methods to obtain and modify the request and response accordingly.
 */
class OAuthEvent implements \GenericEventInterface, StoppableEventInterface {
    use GenericEventTrait;
    use StoppableEventTrait;

    /** @var Request */
    protected $request;

    /** @var Response */
    protected $response;

    /**
     * Creates a new OAuth event.
     * 
     * @param Request $request the OAuth request
     * @param Response $response the OAuth response
     * @param string $eventName the name of the event
     */
    public function __construct(Request $request, Response $response, $eventName = null) {
        $this->setEventName($eventName);
        $this->request = $request;
        $this->response = $response;
    }

    /**
     * Returns the OAuth request.
     * 
     * @return Request the OAuth request
     */
    public function getRequest() {
        return $this->request;
    }

    /**
     * Returns the OAuth response.
     * 
     * @return Response the OAuth response
     */
    public function getResponse() {
        return $this->response;
    }
}

?>