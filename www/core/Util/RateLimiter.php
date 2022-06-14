<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2022
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
 */

namespace SimpleID\Util;

/**
 * A rate limiter.
 *
 * A rate limiter limits the number of requests from a particular source
 * to a particular limit over a defined period.  Once the limit is reached,
 * the server refuses to process any more requests until the defined period
 * is rolled over.
 *
 * This rate limiter uses the FatFree Framework's cache to store rate
 * limit information.
 */
class RateLimiter {
    /** @var string the identifier of the rate limited */
    private $key;

    /** @var int the maximum number of requests from a particular
     * source over the specified period
     */
    private $limit;

    /** @var int $interval the specified period in seconds */
    private $interval;

    /**
     * Creates a rate limiter.
     *
     * @param string $key a string to identify the rate limiter
     * @param int $limit the maximum number of requests from a particular
     * source over the specified period
     * @param int $interval the specified period in seconds
     */
    public function __construct($key = null, $limit = 10, $interval = 10) {
        $this->limit = $limit;
        $this->interval = $interval;
        $this->key = $key;
    }

    /**
     * Increments the rate limiter with a new request from a particular
     * source.
     *
     * The source is specified in the $src parameter.  If $src is not
     * specified, the IP address is used.
     *
     * If $return_remainder is false, this function returns a boolean
     * indicating whether the request should continue to be processed (true),
     * or should be refused (false).
     *
     * If $return_remainder is true, this function returns the number
     * of requests the sources could have before the limit is reached.
     *
     * @param string $src the source
     * @param bool $return_remainder whether to return the remaining number
     * of allowed requests
     * @return bool|int
     */
    public function throttle($src = null, $return_remainder = false) {
        if ($src == null) {
            $f3 = \Base::instance();
            $src = $f3->get('IP');
        }

        $cache = \Cache::instance();
        $cache_name = $this->getCacheName($src);
        $i = $cache->get($cache_name);
        if ($i === false) $i = 0;
        $i++;
        if ($i > $this->limit) { return false;}
        $cache->set($cache_name, $i, $this->interval);
        return ($return_remainder) ? ($this->limit - $i) : true;
    }

    /**
     * Penalises the source by refusing further requests until the
     * period rolls over.
     *
     * The source is specified in the $src parameter.  If $src is not
     * specified, the IP address is used.
     *
     * @param string $src the source
     * @return void
     */
    public function penalize($src = null) {
        if ($src == null) {
            $f3 = \Base::instance();
            $src = $f3->get('IP');
        }

        $cache = \Cache::instance();
        $cache_name = $this->getCacheName($src);
        $cache->set($cache_name, $this->limit, $this->interval);
    }

    /**
     * Resets the rate limiter for a particular source.  This allows
     * the source to make further requests, subject to the limits
     * defined by this rate limiter.
     *
     * The source is specified in the $src parameter.  If $src is not
     * specified, the IP address is used.
     *
     * @param string $src the source
     * @return void
     */
    public function reset($src = null) {
        if ($src == null) {
            $f3 = \Base::instance();
            $src = $f3->get('IP');
        }
        $cache = \Cache::instance();
        $cache->reset(rawurlencode($src) . '.ratelimit');
    }

    /**
     * Resets the rate limiter for all sources.
     * 
     * @return void
     */
    public function resetAll() {
        $cache = \Cache::instance();
        $cache->reset('.ratelimit');
    }

    /**
     * Returns the key
     *
     * @return string the key
     */
    public function getKey() {
        return $this->key;
    }

    /**
     * Returns the limit.
     *
     * @return int the limit
     */
    public function getLimit() {
        return $this->limit;
    }

    /**
     * Returns the interval
     *
     * @return int the interval in seconds
     */
    public function getInterval() {
        return $this->interval;
    }

    /**
     * Returns the name of the cache for the rate limiter in
     * relation to a specified source.
     *
     * @param string $src the source
     * @return string the cache name
     */
    protected function getCacheName($src) {
        return (($this->key == null) ? rawurlencode($this->key) . '.' : '') . rawurlencode($src) . '.ratelimit';
    }
}

?>