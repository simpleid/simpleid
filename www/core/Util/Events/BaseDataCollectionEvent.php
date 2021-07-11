<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021
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
 * Listeners add data by calling the {@link addResult()} method.  If
 * the data to be added is an array, it is merged with the existing data.
 * If the data to be added is a scalar, it is appended to the existing
 * data.
 * 
 * The emitter can retrieve the collected data by calling the
 * {@link getResults()} method.
 */
class BaseDataCollectionEvent implements \GenericEventInterface {
    /** @var string */
    protected $eventName;

    /** @var array */
    protected $results = [];

    /** @var bool */
    protected $recursive;

    /**
     * Creates a data collection event
     * 
     * @param string $eventName the name of the event, or the name
     * @param bool $recursive whether the merge will be recursive
     */
    public function __construct($eventName = null, $recursive = false) {
        if ($eventName == null) {
            // We use static::class instead of self::class or __CLASS__
            // to pick up the name of the subclass instead of
            // BaseDataCollectionEvent (if applicable)
            $this->eventName = static::class;
        } else {
            $this->eventName = $eventName;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getEventName() {
        return $this->eventName;
    }

    /**
     * Adds data to the event.
     * 
     * If the data to be added is an array, it is merged with the existing data.
     * If the data to be added is a scalar, it is appended to the existing data.
     * 
     * @param mixed $result the data to add
     */
    public function addResult($result) {
        if (($result == null) || (is_array($result) && (count($result) == 0))) return;

        // If recursive, result must be an array
        if ($this->recursive && !is_array($result))
            throw new \InvalidArgumentException('result must be an array if recursive merge');
                
        if (is_array($result)) {
            if ($this->recursive) {
                $this->results = array_merge_recursive($this->results, $result);
            } else {
                $this->results = array_merge($this->results, $result);
            }
        } else {
            $this->results[] = $result;
        }
    }

    /**
     * Retrieves the data collected from the event.
     * 
     * If no data is collected, an empty array is returned.
     * 
     * @return array
     */
    public function getResults() {
        return $this->results;
    }
}

?>