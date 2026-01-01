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

namespace SimpleID\Util\Events;

/**
 * A generic event used to collect data with a specified order.
 * 
 * Unlike the {@link BaseDataCollectionEvent}, results are always
 * appended to the results array and never merged.
 *
 */
class OrderedDataCollectionEvent extends BaseDataCollectionEvent {
    /**
     * Creates an ordered data collection event
     * 
     * @param string $eventName the name of the event, or null to use
     * the name of this class
     */
    public function __construct($eventName = null) {
        parent::__construct($eventName, self::MERGE_APPEND);
    }

    /**
     * Adds data to the event with a specified weight.  The weight
     * is used to order the results, to be retrieved by
     * {@link OrderedDataCollectionEvent::getResults()}.
     * 
     * @param array<mixed> $result the data to add
     * @param int $weight the weight
     * @return void
     */
    public function addResult($result, $weight = 0) {
        if ($this->isEmpty($result)) return;
                
        parent::addResult([
            '#data' => $result,
            '#weight' => $weight
        ]);
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