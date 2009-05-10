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
 * $Id: user.inc 87 2008-11-22 09:04:46Z kmo $
 */

/**
 * Functions for storage of user data.
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

?>
