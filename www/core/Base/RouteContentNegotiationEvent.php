<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2026
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
 * An event requesting content negotiation of a route.
 * 
 * The route can be obtained using the {@link getRoute()} method.  This
 * is typically used to store the alias for a named route under the FatFree
 * Framework, although it can be used to store the route pattern as well.
 * 
 * The request body to be processed can be obtained from the
 * {@link getRequest()} method.
 * 
 * If the listener is able to process
 * the request, it should call the {@link stopPropagation()}
 * method to stop further processing.
 */
class RouteContentNegotiationEvent extends BaseEvent implements StoppableEventInterface {
    use StoppableEventTrait;

    /** @var string */
    protected $route;

    /** @var array<string, mixed> */
    protected $request;

    /** @var string|null */
    protected $acceptHeader;

    /**
     * Create a RouteNegotiationEvent
     * 
     * @param string $route the name of the route
     * @param array<string, mixed> $request an array containing the request body
     * @param string|null $accept the HTTP Accept header, or null if the header
     * is not present
     */
    public function __construct($route, $request, $accept) {
        $this->route = $route;
        $this->request = $request;
        $this->acceptHeader = $accept;
    }

    /** @return string */
    public function getRoute() {
        return $this->route;
    }

    /** @return array<string, mixed> */
    public function getRequest() {
        return $this->request;
    }

    /** 
     * Returns the supplied HTTP Accept header, or an empty string if the header
     * is not supplied.
     * 
     * @return string 
     */
    public function getAcceptHeader() {
        return ($this->acceptHeader == null) ? '' : $this->acceptHeader;
    }

    /**
     * Negotiate a content type based on a list of content types provided by
     * the listener.
     * 
     * @param array<string>|string $listener_types an array or comma separated
     * string of content types that the listener can accept
     * @return string|false the negotiated content type, or false if a content
     * type cannot be negotiated
     */
    public function negotiate($listener_types) {
        $client_types = [];

        foreach (explode(',', str_replace(' ', '', $this->getAcceptHeader())) as $item) {
            if (preg_match('/(.+?)(?:;q=([\d\.]+)|$)/', $item, $parts)) {
                $client_types[$parts[1]] = isset($parts[2]) ? $parts[2] : 1.0;
            }
        }

        if (!$client_types) {
            $client_types['*/*'] = 1.0;
        } else {
            krsort($client_types);
            arsort($client_types);
        }
        
        if (is_string($listener_types)) $listener_types = explode(',', $listener_types);

        foreach ($client_types as $client_type => $q) {
            if ($q && $out = preg_grep('!'. str_replace('\*', '.*', preg_quote($client_type,'!')) . '!', $listener_types)) {
                return current($out);
            }
        }
        return FALSE;
    }
}

?>