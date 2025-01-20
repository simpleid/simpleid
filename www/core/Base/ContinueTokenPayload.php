<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2025
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

 
class ContinueTokenPayload implements JsonSerializable {
    /** @var string */
    private $method = null;  // mt

    /** @var string */
    private $route = null;   // rt

    /** @var array<string, mixed> */
    private $request = null; // rq

    /**
     * @param array<string, mixed> $payload the payload from the security token
     */
    public function __construct(?array $payload = []) {
        if (isset($payload['mt'])) $this->method = $payload['mt'];
        if (isset($payload['rt'])) $this->route = $payload['rt'];
        if (isset($payload['rq'])) $this->request = $payload['rq'];
    }

    public function getMethod(): string {
        return ($this->method == null) ? 'GET' : $this->method;
    }

    public function setMethod(string $method): self {
        $this->method = $method;
        return $this;
    }

    public function getRoute(): string {
        return ($this->route == null) ? '/' : $this->route;
    }

    public function setRoute(string $route): self {
        $this->route = $route;
        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function getRequest(): array {
        return ($this->request == null) ? [] : $this->request;
    }

    /**
     * @param array<string, mixed> $request
     */
    public function setRequest(array $request): self {
        $this->request = $request;
        return $this;
    }

    public function jsonSerialize(): mixed {
        $data = [];
        if ($this->method != null) $data['mt'] = $this->method;
        if ($this->route != null) $data['rt'] = $this->route;
        if ($this->request != null) $data['rq'] = $this->request;
        return $data;
    }
}

?>