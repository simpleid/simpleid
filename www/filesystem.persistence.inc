<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-9
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
 * Functions for persistent storage via the file system.
 *
 * @package simpleid
 * @filesource
 */


/**
 * Returns whether the user name exists in the user store.
 *
 * @param string $uid the name of the user to check
 * @param bool whether the user name exists
 */
function persistence_user_exists($uid) {
    $identity_file = SIMPLEID_IDENTITIES_DIR . "/$uid.identity";
    return (file_exists($identity_file));
}

/**
 * Loads user data for a specified user name.
 *
 * The user name must exist.  You should check whether the user name exists with
 * the {@link persistence_user_exists()} function
 *
 * @param string $uid the name of the user to load
 * @return mixed data for the specified user
 */
function persistence_user_load($uid) {
    $identity_file = SIMPLEID_IDENTITIES_DIR . "/$uid.identity";
    return parse_ini_file($identity_file, TRUE);
}

/**
 * Finds the user name from a specified OpenID Identity URI.
 *
 * @param string $identity the Identity URI of the user to load
 * @return string the user name for the Identity URI, or NULL if no user has
 * the specified Identity URI
 */
function persistence_uid_from_identity($uid) {
    $r = NULL;
    
    $dir = opendir(SIMPLEID_IDENTITIES_DIR);
    
    while (($file = readdir($dir)) !== false) {
        $filename = SIMPLEID_IDENTITIES_DIR . '/' . $file;                        
        
        if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.identity$/', $file, $matches))) continue;
        
        $uid = $matches[1];
        $test_user = persistence_user_load($uid);
        
        cache_set('identity', $test_user['identity'], $uid);
    
        if ($test_user['identity'] == $identity) {
            $r = $uid;
        }
    }
        
    closedir($dir);
    
    return $r;
}

/**
 * Saves the user's preferences and other data in relation to a relying party.
 *
 * @param string $uid the user name
 * @param string $realm the openid.realm of the relying party
 * @param array $details an associative array of the data to save
 * @see cache_set()
 */
function persistence_rp_save($uid, $realm, $details = array()) {
    $now = time();
    
    $rps = persistence_rp_load_all($uid);
    
    if ($rps == NULL) $rps = array();

    if (!isset($rps[$realm])) {
        if ($details['auto_release'] != 0) {
            $details['auto_release'] = 1;
        }
        
        $rps[$realm] = array_merge($details, array('uid' => $uid, 'realm' => $realm, 'first_time' => $now, 'last_time' => $now));
    } else {
        $rps[$realm] = array_merge($details, $rps[$realm]);
        $rps[$realm]['last_time'] = $now;
    }
    cache_set('rp', $uid, $rps);
}

/**
 * Loads the user's preferences and other data in relation to a relying party.
 *
 * @param string $uid the user name
 * @param string $realm the openid.realm of the relying party
 * @return array an associative array of the data
 * @see cache_get()
 */
function persistence_rp_load($uid, $realm) {
    $rps = cache_get('rp', $uid);
    if (isset($rps[$realm])) {
        return $rps[$realm];
    } else {
        return NULL;
    }
}

/**
 * Loads the user's preferences and other data in relation to all relying parties.
 *
 * @param string $uid the user name
 * @return array an associative array of the data, with the openid.realm URIs as
 * key
 */
function persistence_rp_load_all($uid) {
    return cache_get('rp', $uid);
}

/**
 * Saves the user's preferences and other data in relation to all relying parties.
 *
 * @param string $uid the user name
 * @param array $rps an associative array of the data as obtained from the
 * {@link persistence_rp_load_all()} function
 */
function persistence_rp_save_all($uid, $rps) {
    cache_set('rp', $uid, $rps);
}

?>
