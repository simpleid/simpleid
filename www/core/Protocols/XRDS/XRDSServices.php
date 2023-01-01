<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2023
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

namespace SimpleID\Protocols\XRDS;

/**
 * A collection of discovered XRDS services.
 *
 * The collection can be queried using the {@link getByType()} and
 * {@link getById()} functions.
 */
class XRDSServices {

    /** @var array<array<string, mixed>> Array of discovered services */
    private $services = [];

    /**
     * Adds a service.
     *
     * @param array<string, mixed> $service the service to add
     * @param bool $sort whether to sort the services in place
     * @return void
     */
    public function add($service, $sort = true) {
        $this->services[] = $service;
        if ($sort) uasort($this->services, '\SimpleID\Protocols\XRDS\XRDSServices::sortByPriority');
    }

    /**
     * Returns the number of services.
     *
     * @return int the number of services
     */
    public function getLength() {
        return count($this->services);
    }

    /**
     * Obtains information on discovered services of
     * a particular type.
     *
     * @param string $type the URI of the type of service to obtain
     * @return array<array<string, mixed>> an array of matching services, or an empty array of no services
     * match
     */
    public function getByType($type) {
        $matches = [];
        
        foreach ($this->services as $service) {
            foreach ($service['type'] as $service_type) {
                if ($service_type == $type) $matches[] = $service;
            }
        }
        return $matches;
    }

    /**
     * Obtains information on a discovered service of
     * a specified ID.
     *
     * @param string $id the XML ID of the service in the XRDS document
     * @return array<string, mixed>|null the matching service, or NULL of no services
     * are found
     */
    public function getById($id) {
        foreach ($this->services as $service) {
            if ($service['#id'] == $id) return $service;
        }
        return NULL;
    }

    /**
     * Callback function to sort service and URI elements based on priorities
     * specified in the XRDS document.
     *
     * The XRDS specification allows multiple instances of certain elements, such
     * as Service and URI.  The specification allows an attribute called priority
     * so that the document creator can specify the order the elements should be used.
     *
     * @param array<string, mixed> $a
     * @param array<string, mixed> $b
     * @return int
     */
    static public function sortByPriority($a, $b) {
        if (!isset($a['#priority']) && !isset($b['#priority'])) return 0;
        
        // if #priority is missing, #priority is assumed to be infinity
        if (!isset($a['#priority'])) return 1;
        if (!isset($b['#priority'])) return -1;
        
        if ($a['#priority'] == $b['#priority']) return 0;
        return ($a['#priority'] < $b['#priority']) ? -1 : 1;
    }
}

?>
