<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2026
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
    protected $key;

    /** @var int the maximum number of requests from a particular
     * source over the specified period
     */
    protected $limit;

    /** @var int $interval the specified period in seconds */
    protected $interval;

    /**
     * Creates a rate limiter.
     *
     * @param string $key a string to identify the rate limiter
     * @param int $limit the maximum number of requests from a particular
     * source over the specified period
     * @param int $interval the specified period in seconds
     */
    public function __construct($key, $limit = 10, $interval = 10) {
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
     * The rate limiter is incremented by the amount specified by the
     * $weight parameter.
     *
     * This function returns a boolean indicating whether the request
     * should continue to be processed (true), or should be refused (false).
     *
     * @param string $src the source
     * @param int $weight
     * @return bool
     */
    public function throttle($src = null, $weight = 1) {
        if ($src == null) $src = $this->getDefaultSource();

        $cache = \Cache::instance();
        $cache_name = $this->getCacheName($src);
        $entry = $cache->get($cache_name);
        if (($entry === false) || (time() >= $entry['expires'])) $entry = ['count' => 0, 'expires' => time() + $this->interval ];
        $entry['count'] += $weight;
        if ($entry['count'] > $this->limit) { return false;}
        $cache->set($cache_name, $entry, $this->interval);
        return true;
    }

    /**
     * Returns the number of requests remaining for the source before the
     * limit is reached.
     *
     * The source is specified in the $src parameter.  If $src is not
     * specified, the IP address is used.
     *
     * @param string $src the source
     * @return int
     */
    public function remainder($src = null) {
        if ($src == null) $src = $this->getDefaultSource();

        $cache = \Cache::instance();
        $cache_name = $this->getCacheName($src);
        $entry = $cache->get($cache_name);
        if ($entry === false) return $this->limit;
        return intval($this->limit - $entry['count']);
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
        if ($src == null) $src = $this->getDefaultSource();

        $cache = \Cache::instance();
        $cache_name = $this->getCacheName($src);
        $entry = $cache->get($cache_name);
        if ($entry === false) {
            $entry = ['count' => $this->limit, 'expires' => time() + $this->interval ];
        } else {
            $entry['count'] = $this->limit;
        };
        $cache->set($cache_name, $entry, $this->interval);
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
        if ($src == null) $src = $this->getDefaultSource();
        
        $cache = \Cache::instance();
        $cache_name = $this->getCacheName($src);
        $cache->reset($cache_name);
    }

    /**
     * Resets the rate limiter for all sources.
     * 
     * @return void
     */
    public function resetAll() {
        $this->reset('');
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
     * Returns the IP address using the default source for the rate limiter.
     *
     * The default source is the {@link https://fatfreeframework.com/3.8/quick-reference#IP IP}
     * hive variable from the FatFree Framework, which resolves reverse proxies
     * using the `Client-IP` and the `X-Forwarded-For` headers.
     *
     * @return string the IP address
     */
    protected function getDefaultSource() {
        $f3 = \Base::instance();
        return $f3->get('IP');
    }

    /**
     * Returns the name of the cache for the rate limiter in
     * relation to a specified source.
     *
     * @param string $src the source
     * @return string the cache name
     */
    protected function getCacheName($src) {
        return rawurlencode($src) . '.' . rawurlencode($this->key) . '.ratelimit';
    }
}

?>
