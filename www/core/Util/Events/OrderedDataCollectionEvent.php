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
 * A generic event used to collect data in an ordered way.
 *
 */
class OrderedDataCollectionEvent extends BaseEvent implements \GenericEventInterface {
    use GenericEventTrait;

    /** @var array<array<mixed>> */
    protected $results = [];

    /**
     * Creates a data collection event
     * 
     * @param string $eventName the name of the event, or the name
     */
    public function __construct($eventName = null) {
        $this->setEventName($eventName);
    }

    /**
     * Adds data to the event.
     * 
     * Unlike the {@link BaseDataCollectionEvent}, results are always
     * appended to the results array and never merged
     * 
     * @param array<mixed> $result the data to add
     * @param int $weight the weight
     * @return void
     */
    public function addResult($result, $weight = 0) {
        if ($result == null) return;
                
        $this->results[] = [
            '#data' => $result,
            '#weight' => $weight
        ];
    }

    /**
     * Retrieves the data collected from the event, ordered by the
     * weight, from lowest to highest.
     * 
     * @return array<mixed>
     */
    public function getResults() {
        uasort($this->results, function($a, $b) { if ($a['#weight'] == $b['#weight']) { return 0; } return ($a['#weight'] < $b['#weight']) ? -1 : 1; });
        return array_map(function($a) { return $a['#data']; }, $this->results);
    }
}

?>