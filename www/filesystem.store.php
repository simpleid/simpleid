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
 * In general, there are three different sets of data which SimpleID needs
 * to store:
 *
 * - transient data (e.g. OpenID associations, sessions, auto-login)
 * - application data (e.g. salt for form tokens)
 * - user data (e.g. user names, passwords and settings)
 *
 * Prior to version 0.7, both transient data and application data are stored
 * using {@link cache.inc}.  From version 0.7, application data are now
 * stored separately from the cache.
 *
 * Prior to version 0.7, user data is only stored in the identity file, to which
 * SimpleID cannot write.  This means that if the user wishes to change a setting,
 * he or she will need to edit the identity file manually.  Other user settings
 * (e.g. RP preferences) are stored using {@link cache.inc}
 *
 * From version 0.7, user data is stored in two files, one is the identity
 * file, the other is the user store file, which SimpleID can write.
 *
 * @package simpleid
 * @filesource
 */

/**
 * This variable is a cache of SimpleID's application settings.  It is populated
 * progressively as {@link store_get()} is called.
 *
 * @global array $simpleid_settings
 */
$simpleid_settings = array();

/**
 * Returns whether the user name exists in the user store.
 *
 * @param string $uid the name of the user to check
 * @return bool whether the user name exists
 */
function store_user_exists($uid) {
    if (_store_is_valid_name($uid)) {
        $identity_file = SIMPLEID_IDENTITIES_DIR . "/$uid.identity";
        return (file_exists($identity_file));
    } else {
        return false;
    }
}

/**
 * Loads user data for a specified user name.
 *
 * The user name must exist.  You should check whether the user name exists with
 * the {@link store_user_exists()} function
 *
 * @param string $uid the name of the user to load
 * @return mixed data for the specified user
 */
function store_user_load($uid) {
    if (!_store_is_valid_name($uid)) return array();
    $store_file = SIMPLEID_STORE_DIR . "/$uid.usrstore";
    
    if (file_exists($store_file)) {
        $data = unserialize(file_get_contents($store_file));
    } else {
        $data = array();
    }
    
    $identity_file = SIMPLEID_IDENTITIES_DIR . "/$uid.identity";
    $data = array_merge($data, parse_ini_file($identity_file, TRUE));
    
    return $data;
}

/**
 * Returns the time which a user's data has been updated.
 *
 * The user name must exist.  You should check whether the user name exists with
 * the {@link store_user_exists()} function.
 *
 * The time returned can be based on the identity file,
 * the user store file, or the latter of the two.
 *
 * @param string $uid the name of the user to obtain the update time
 * @param string $type one of: 'identity' (identity file), 'usrstore' (user store
 * file) or NULL (latter of the two)
 * @return int the updated time
 */ 
function store_user_updated_time($uid, $type = NULL) {
    if (!_store_is_valid_name($uid)) return NULL;
    
    $identity_file = SIMPLEID_IDENTITIES_DIR . "/$uid.identity";
    $identity_time = filemtime($identity_file);
    
    $store_file = SIMPLEID_STORE_DIR . "/$uid.usrstore";
    if (file_exists($store_file)) {
        $store_time = filemtime($store_file);
    } else {
        $store_time = NULL;
    }
    
    if ($type == 'identity') {
        return $identity_time;
    } elseif ($type == 'usrstore') {
        return $store_time;
    } elseif ($type == NULL) {
        return ($identity_time > $store_time) ? $identity_time : $store_time;
    } else {
        return NULL;
    }
}


/**
 * Finds the user name from a specified OpenID Identity URI.
 *
 * @param string $identity the Identity URI of the user to load
 * @return string the user name for the Identity URI, or NULL if no user has
 * the specified Identity URI
 */
function store_get_uid($identity) {
    $uid = cache_get('identity', $identity);
    if ($uid !== NULL) return $uid;
    
    $r = NULL;
    
    $dir = opendir(SIMPLEID_IDENTITIES_DIR);
    
    while (($file = readdir($dir)) !== false) {
        $filename = SIMPLEID_IDENTITIES_DIR . '/' . $file;
        
        if (is_link($filename)) $filename = readlink($filename);
        if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.identity$/', $file, $matches))) continue;
        
        $uid = $matches[1];
        $test_user = store_user_load($uid);
        
        cache_set('identity', $test_user['identity'], $uid);
    
        if ($test_user['identity'] == $identity) {
            $r = $uid;
        }
    }
        
    closedir($dir);
    
    return $r;
}

/**
 * Finds the user name from a specified client SSL certificate string.
 *
 * The client SSL certificate string comprises the certificate's serial number
 * (in capitals hex notation) and the distinguished name of the certificate's issuer
 * (with components joined using slashes), joined using a semi-colon.
 *
 *
 * @param string $cert the client SSL certificate string of the user to load
 * @return string the user name matching the client SSL certificate string, or NULL if no user has
 * client SSL certificate string
 */
function store_get_uid_from_cert($cert) {
    $uid = cache_get('cert', $cert);
    if ($uid !== NULL) return $uid;
    
    $r = NULL;
    
    $dir = opendir(SIMPLEID_IDENTITIES_DIR);
    
    while (($file = readdir($dir)) !== false) {
        $filename = SIMPLEID_IDENTITIES_DIR . '/' . $file;
        
        if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.identity$/', $file, $matches))) continue;
        
        $uid = $matches[1];
        $test_user = store_user_load($uid);
        
        if (isset($test_user['certauth']['cert'])) {
            if (is_array($test_user['certauth']['cert'])) {
                foreach ($test_user['certauth']['cert'] as $test_cert) {
                    if (trim($test_cert) != '') cache_set('cert', $test_cert, $uid);
                }
                foreach ($test_user['certauth']['cert'] as $test_cert) {
                    if ((trim($test_cert) != '') && ($test_cert == $cert))  $r = $uid;
                }
            } else {
                if (trim($test_cert) != '') {
                    cache_set('cert', $test_user['certauth']['cert'], $uid);
                    if ($test_user['certauth']['cert'] == $cert) $r = $uid;
                }
            }
        }
    }
        
    closedir($dir);
    
    return $r;
}

/**
 * Saves user data for a specific user name.
 *
 * This data is stored in the user store file.
 *
 * @param string $uid the name of the user
 * @param array $data the data to save
 * @param array $exclude an array of keys to exclude from the user store file.
 * These are generally keys which are stored in the identity file.
 *
 * @since 0.7
 */
function store_user_save($uid, $data, $exclude = array()) {
    foreach ($exclude as $key) {
        if (isset($data[$key])) unset($data[$key]);
    }
    
    if (!_store_is_valid_name($uid)) {
        trigger_error("Invalid user name for filesystem store", E_USER_ERROR);
        return;
    }
    
    $store_file = SIMPLEID_STORE_DIR . "/$uid.usrstore";
    $file = fopen($store_file, 'w');
    fwrite($file, serialize($data));
    fclose($file);
}

/**
 * Loads an application setting.
 *
 * @param string $name the name of the setting to return
 * @param mixed $default the default value to use if this variable has never been set
 * @return mixed the value of the setting
 *
 */
function store_get($name, $default = NULL) {
    global $simpleid_settings;
    
    if (!_store_is_valid_name($name)) return $default;
    
    if (!isset($simpleid_settings[$name])) {
        $setting_file = SIMPLEID_STORE_DIR . "/$name.setting";
        
        if (file_exists($setting_file)) {
            $simpleid_settings[$name] = unserialize(file_get_contents($setting_file));
        } else {
            return $default;
        }
    }
    
    return $simpleid_settings[$name];
}

/**
 * Saves an application setting.
 *
 * @param string $name the name of the setting to save
 * @param mixed $value the value of the setting
 *
 */
function store_set($name, $value) {
    global $simpleid_settings;
    
    if (!_store_is_valid_name($name)) {
        trigger_error("Invalid setting name for filesystem store", E_USER_ERROR);
        return;
    }
    
    $simpleid_settings[$name] = $value;
    
    $setting_file = SIMPLEID_STORE_DIR . "/$name.setting";
    $file = fopen($setting_file, 'w');
    fwrite($file, serialize($value));
    fclose($file);
}

/**
 * Deletes an application setting.
 *
 * @param string $name the name of the setting to delete
 *
 */
function store_del($name) {
    global $simpleid_settings;
    
    if (!_store_is_valid_name($name)) {
        trigger_error("Invalid setting name for filesystem store", E_USER_ERROR);
        return;
    }
    
    if (isset($simpleid_settings[$name])) unset($simpleid_settings[$name]);
    
    $setting_file = SIMPLEID_STORE_DIR . "/$name.setting";
    if (file_exists($setting_file)) unlink($setting_file);
}

/**
 * Determines whether a name is a valid name for use with this store.
 *
 * For file system storage, a name is not valid if it contains either a
 * directory separator (i.e. / or \).
 *
 * @param string $name the name to check
 * @return boolean whether the name is valid for use with this store 
 *
 */
function _store_is_valid_name($name) {
    return preg_match('!\A[^/\\\\]*\z!', $name);
}
?>
