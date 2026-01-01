<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2025-2026
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

use JsonSerializable;

/**
 * Stores the state of a request.
 * 
 * Request states are typically serialised through
 * {@link SimpleID\Util\SecurityToken} and then passed in a URL,
 * to be consumed by the {@link IndexModule::continue()} function.
 */ 
class RequestState implements JsonSerializable {
    /** 
     * The HTTP method.
     * 
     * @var string 
     */
    private $method = null;

    /** 
     * the FatFree routing path
     * 
     * @var string 
     */
    private $route = null;

    /**
     * The request parameters
     * 
     * @var array<string, mixed> 
     */
    private $params = null;

    /**
     * Creates a new request state.
     * 
     * Call the constructor with an empty array to create a blank request
     * state.  Alternatively, the constructor can be supplied with the payload
     * from a security token to populate the request state.
     * 
     * The security token payload can contain the following keys
     *
     * - mt the HTTP method (e.g. GET, POST)
     * - rt the FatFree routing path
     * - rq an array containing the request parameters
     * 
     * @param array<string, mixed> $payload the payload from the security token
     */
    public function __construct(array $payload = []) {
        if (isset($payload['mt'])) $this->method = $payload['mt'];
        if (isset($payload['rt'])) $this->route = $payload['rt'];
        if (isset($payload['rq'])) $this->params = $payload['rq'];
    }

    /**
     * Gets the HTTP method.  If the HTTP method is not set, this method
     * returns `GET`.
     * 
     * @return string the HTTP method.
     */
    public function getMethod(): string {
        return ($this->method == null) ? 'GET' : $this->method;
    }

    /**
     * Sets the HTTP method.
     * 
     * @param string $method the HTTP method
     */
    public function setMethod(string $method): self {
        $this->method = $method;
        return $this;
    }

    /**
     * Gets the FatFree routing path.  If the routing path is not set,
     * this method returns `/`.
     * 
     * @return string the routing path
     */
    public function getRoute(): string {
        return ($this->route == null) ? '/' : $this->route;
    }

    /**
     * Sets the routing path
     * 
     * @param string $route the routing path
     */
    public function setRoute(string $route): self {
        $this->route = $route;
        return $this;
    }

    /**
     * Gets the request parameters.
     * 
     * @return array<string, mixed>
     */
    public function getParams(): array {
        return ($this->params == null) ? [] : $this->params;
    }

    /**
     * Sets the request parameters.
     * 
     * @param array<string, mixed> $params
     */
    public function setParams(array $params): self {
        $this->params = $params;
        return $this;
    }

    /**
     * Returns the FatFree route pattern.
     * 
     * The FatFree route pattern contains the HTTP method and the 
     * routing path.
     * 
     * The pattern can be used with the `mock()` method in the
     * FatFree Framework.
     * 
     * @return string the routing pattern
     */
    public function toF3RoutePattern(): string {
        return $this->getMethod() . ' ' . $this->getRoute();
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): mixed {
        $data = [];
        if ($this->method != null) $data['mt'] = $this->method;
        if ($this->route != null) $data['rt'] = $this->route;
        if ($this->params != null) $data['rq'] = $this->params;
        return $data;
    }
}

?>