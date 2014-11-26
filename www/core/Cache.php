<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014
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

namespace SimpleID;

/**
 * Interface for caching and persistence.
 *
 */
interface Cache {
    /**
     *  Stores data into the cache.
     *
     * @param string $type the type of data in the cache
     * @param string $key an identifier
     * @param mixed $data the data to store
     * @param int $time if present, sets the modification time of the cache file to this
     * time
     */ 
    function set($type, $key, $data, $time = NULL);

    /**
     * Obtains data from the cache.
     *
     * @param string $type the type of data in the cache
     * @param string $key an identifier
     * @return mixed the data associated with the type and key, or NULL if the cache
     * does not contain the requested data.
     */
    function get($type, $key);

    /**
     * Obtains all data of a particular type from the cache.
     *
     * @param string $type the type of data in the cache
     * @return mixed an array of data associated with the type, or NULL if the cache
     * does not contain the requested data.
     */
    function getAll($type);

    /**
     * Deletes data from the cache.
     *
     * @param string $type the type of data in the cache
     * @param string $key an identifier
     */
    function delete($type, $key);

    /**
     * Garbage collects data stored the cache.  Data is deleted if it was stored
     * for longer than the specified expiry.
     *
     * The parameter to this function takes either an integer or an array.  If the
     * parameter is an integer, everything in the cache older than the specified
     * time (in seconds) will be deleted.  If the parameter is an array, 
     * cache items of the type specified in the key to the array, older than the
     * corresponding value will be deleted.
     *
     * @param int|array $params the expiry time, in seconds, after which data will be deleted,
     * or an array specifiying the expiry time for each type
     */
    function expire($params);

    /**
     * Returns the time remaining, in seconds, before the data associated with the
     * type and key become subject to garbage collection by {@link #expire()}.
     *
     * @param string $type the type of data in the cache
     * @param string $key an identifier
     * @param int $expiry the expiry time, in seconds, which would be passed onto the
     * {@link cache_gc()} function
     * @return int the time remaining before expiry, rounded downwards,
     * or zero if the cache does not contain the requested data
     */
    function ttl($type, $key, $expiry);

}

?>
