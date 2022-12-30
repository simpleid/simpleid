<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-9
 *
 * Includes code Drupal OpenID module (http://drupal.org/project/openid)
 * Rowan Kerr <rowan@standardinteractive.com>
 * James Walker <james@bryght.com>
 *
 * Copyright (C) Rowan Kerr and James Walker
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
 * $Id$
 */

/**
 * Functions for caching and persistence.
 *
 * @package simpleid
 * @filesource
 */
 
/**
 *  Stores data into the cache.
 *
 * @param string $type the type of data in the cache
 * @param string $key an identifier
 * @param mixed $data the data to store
 * @param int $time if present, sets the modification time of the cache file to this
 * time
 */ 
function cache_set($type, $key, $data, $time = NULL) {
    $filename = _cache_get_name($type, $key);
    if (!file_exists(dirname($filename))) mkdir(dirname($filename), 0775, true);
    $file = fopen($filename, 'w');
    fwrite($file, serialize($data));
    fclose($file);
    
    if ($time != NULL) {
        touch($filename, $time);
    }
}

/**
 * Obtains data from the cache.
 *
 * @param string $type the type of data in the cache
 * @param string $key an identifier
 * @return mixed the data associated with the type and key, or NULL if the cache
 * does not contain the requested data.
 */
function cache_get($type, $key) {
    $filename = _cache_get_name($type, $key);
    
    if (!file_exists($filename)) return NULL;
    
    return unserialize(file_get_contents($filename));
}

/**
 * Obtains all data of a particular type from the cache.
 *
 * @param string $type the type of data in the cache
 * @return mixed an array of data associated with the type, or NULL if the cache
 * does not contain the requested data.
 */
function cache_get_all($type) {
    $r = array();
    
    if (!is_dir(CACHE_DIR . '/' . $type)) return $r;
    $dir = opendir(CACHE_DIR . '/' . $type);
    
    while (($file = readdir($dir)) !== false) {
        $filename = CACHE_DIR . '/' . $type . '/' . $file;
        
        if (filetype($filename) != "file") continue;
        
        $r[] = unserialize(file_get_contents($filename));
    }
    
    closedir($dir);
    
    return $r;
}

/**
 * Deletes data from the cache.
 *
 * @param string $type the type of data in the cache
 * @param string $key an identifier
 */
function cache_delete($type, $key) {
    $filename = _cache_get_name($type, $key);
    if (file_exists($filename)) unlink($filename);
}

/**
 * Garbage collects data stored the cache.  Data is deleted if it was stored
 * for longer than the specified expiry.
 *
 * This function is deprecated, use {@link cache_expire()}.
 *
 * @param int $expiry the expiry time, in seconds, after which data will be deleted
 * @param string $type the type of data in the cache
 * @deprecated
 */
function cache_gc($expiry, $type = NULL) {
    if ($type == NULL) {
        $dir = opendir(CACHE_DIR);

        while (($file = readdir($dir)) !== false) {
            $filename = CACHE_DIR . '/' . $file;
            if (in_array(filetype($filename), array('dir', 'link')))
                cache_gc($expiry, $file);
        }
    } else {
        if (!is_dir(CACHE_DIR . '/' . $type)) return;
        $dir = opendir(CACHE_DIR . '/' . $type);
        while (($file = readdir($dir)) !== false) {
            $filename = CACHE_DIR . '/' . $type . '/' . $file;
        
            if ((filetype($filename) == "file") && (filectime($filename) < time() - $expiry))
                unlink($filename);
        }
    }
    
    closedir($dir);
}

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
 * This function is deprecated, use {@link cache_expire()}.
 *
 * @param int|array $params the expiry time, in seconds, after which data will be deleted,
 * or an array specifiying the expiry time for each type
 */
function cache_expire($params) {

    $dirs = array();
    array_push($dirs, CACHE_DIR);
    while (sizeof($dirs)) {
        $dirname = array_pop($dirs);
        if (($dir = opendir($dirname)) === false) {
            continue;
        }

        while (($file = readdir($dir)) !== false) {
            $expiry = NULL;
            if ($file == '.' || $file == '..') {
                continue;
            }
            $filename = $dirname . '/' . $file;

            if (is_dir($filename)) {
                array_push($dirs, $filename);
                continue;
            }

            if (is_int($params)) {
                $expiry = $params;
            } elseif (is_array($params)) {
                foreach ($params as $type => $param) {
                    if (strpos($filename, $type) !== false) {
                        $expiry = $param;
                        break;
                    }
                }
            }

            if (!is_null($expiry) && (filetype($filename) == "file") && (filectime($filename) < time() - $expiry)) {
                unlink($filename);
            }
        }

        closedir($dir);
    }
}

/**
 * Returns the time remaining, in seconds, before the data associated with the
 * type and key become subject to garbage collection by {@link cache_gc()}.
 *
 * @param string $type the type of data in the cache
 * @param string $key an identifier
 * @param int $expiry the expiry time, in seconds, which would be passed onto the
 * {@link cache_gc()} function
 * @return int the time remaining before expiry, rounded downwards,
 * or zero if the cache does not contain the requested data
 * @since 0.8
 */
function cache_ttl($type, $key, $expiry) {
    $filename = _cache_get_name($type, $key);
    
    if (!file_exists($filename)) return 0;
    
    return filectime($filename) - (time() - $expiry) - 1;
}

/**
 * Returns the name of the cache data file, given a type and an identifier.
 *
 * @param string $type the type of data in the cache
 * @param string $key an identifier
 * @return string a file name
 */
function _cache_get_name($type, $key) {
    return CACHE_DIR . '/' . $type . '/' . md5($key) . '.cache';
}

?>
