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
 * A generic event used to collect data.
 * 
 * This class implements f3-event-dispatcher's GenericEventInterface, and
 * therefore the event name is specified by the `$eventName` parameter
 * passed in the constructor.
 * 
 * Listeners add data by calling the {@link addResult()} method.  How
 * this is added to the existing data depends on the merge strategy:
 * 
 * - If the merge strategy is `MERGE_APPEND`, then the result
 *   is appended to the existing data
 * - If the merge strategy is `MERGE_PLAIN`, then the result
 *   is merged to the existing data using `array_merge`
 * - If the merge strategy is `MERGE_RECURSIVE`, then the result
 *   is merged to the existing data using `array_merge_recursive`
 * - If the merge strategy is `MERGE_DEFAULT`, then the result is
 *   appended if it is a scalar, or merged if it is an array
 * 
 * The emitter can retrieve the collected data by calling the
 * {@link getResults()} method.
 */
class BaseDataCollectionEvent extends BaseEvent implements \GenericEventInterface {
    use GenericEventTrait;

    public const MERGE_DEFAULT = 0;
    public const MERGE_APPEND = 1;
    public const MERGE_PLAIN = 2;
    public const MERGE_RECURSIVE = 3;

    // alias
    public const MERGE_MERGE = self::MERGE_PLAIN;

    /** @var array<mixed> */
    protected $results = [];

    /** @var int */
    protected $mergeStrategy;

    /**
     * Creates a data collection event
     * 
     * @param string $eventName the name of the event, or the null to use the
     * name of this class
     * @param int $mergeStrategy whether the merge will be mergeStrategy
     */
    public function __construct($eventName = null, $mergeStrategy = self::MERGE_DEFAULT) {
        $this->setEventName($eventName);
        $this->mergeStrategy = $mergeStrategy;
    }


    /**
     * Adds data to the event.
     * 
     * If the data to be added is an array, it is merged with the existing data.
     * If the data to be added is a scalar, it is appended to the existing data.
     * 
     * @param mixed $result the data to add
     * @return void
     */
    public function addResult($result) {
        if ($this->isEmpty($result)) return;

        // If recursive, result must be an array
        if (($this->mergeStrategy == self::MERGE_RECURSIVE) && !is_array($result))
            throw new \InvalidArgumentException('result must be an array if recursive merge');

        if ($this->mergeStrategy == self::MERGE_DEFAULT) {
            $merge_strategy = (is_array($result)) ? self::MERGE_PLAIN : self::MERGE_APPEND;
        } else {
            $merge_strategy = $this->mergeStrategy;
        }

        switch ($merge_strategy) {
            case self::MERGE_APPEND:
                $this->results[] = $result;
                break;
            case self::MERGE_PLAIN:
                $this->results = array_merge($this->results, $result);
                break;
            case self::MERGE_RECURSIVE:
                $this->results = array_merge_recursive($this->results, $result);
                break;
        }
    }

    /**
     * Retrieves the data collected from the event.
     * 
     * If no data is collected, an empty array is returned.
     * 
     * @return array<mixed>
     */
    public function getResults() {
        return $this->results;
    }

    /**
     * Returns whether any data have been collected by the
     * event.
     * 
     * @return bool true if data have been collected
     */
    public function hasResults() {
        return (count($this->results) > 0);
    }

    /**
     * Returns whether a variable is "empty".
     * 
     * A variable is empty if it is null or is a zero-length array.
     * 
     * @param mixed $x the variable
     * @return bool true if the variable is empty
     */
    protected function isEmpty($x) {
        return (($x == null) || (is_array($x) && (count($x) == 0)));
    }
}

?>