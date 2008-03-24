<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007
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
 *  Stores data into the cache.
 *
 * @param $type the type of data in the cache
 * @param $key an identifier
 * @param $data the data to store
 * @param $time if present, sets the modification time of the cache file to this
 * time
 */ 
function cache_set($type, $key, $data, $time = NULL) {
    $filename = _cache_get_name($type, $key);
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
 * @param $type the type of data in the cache
 * @param $key an identifier
 * @return the data associated with the type and key, or NULL if the cache
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
 * @param $type the type of data in the cache
 * @return an array of data associated with the type, or NULL if the cache
 * does not contain the requested data.
 */
function cache_get_all($type) {
    $r = array();
    
    $dir = opendir(SIMPLEID_CACHE_DIR);
    
    while (($file = readdir($dir)) !== false) {
        $filename = SIMPLEID_CACHE_DIR . '/' . $file;
        
        if ((filetype($filename) != "file") || (strpos($file, $type . '-') !== 0)) continue;
        
        $r[] = unserialize(file_get_contents($filename));
    }
    
    closedir($dir);
    
    return $r;
}

/**
 * Deletes data from the cache.
 *
 * @param $type the type of data in the cache
 * @param $key an identifier
 */
function cache_delete($type, $key) {
    unlink(_cache_get_name($type, $key));
}

/**
 * Garbage collects data stored the cache.  Data is deleted if it was stored
 * for longer than the specified expiry
 *
 * @param $expiry the expiry time, in seconds, after which data will be deleted
 * @param $type the type of data in the cache
 */
function cache_gc($expiry, $type = NULL) {
    $dir = opendir(SIMPLEID_CACHE_DIR);
    
    while (($file = readdir($dir)) !== false) {
        $filename = SIMPLEID_CACHE_DIR . '/' . $file;
        
        if (($type != NULL) && (strpos($file, $type . '-') !== 0)) continue;
        
        if ((filetype($filename) == "file") && (filectime($filename) < time() - $expiry)) {
            unlink($filename);
        }
    }
    
    closedir($dir);
}

function _cache_get_name($type, $key) {
    return SIMPLEID_CACHE_DIR . '/' . $type . '-' . md5($key) . '.cache';
}

?>
