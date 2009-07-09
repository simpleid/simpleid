<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2009
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

 
$upgrade_access_check = FALSE;

/* ----- Do not modify anything following this line ------------------------- */

include_once "version.inc";
include_once "config.inc";
include_once "config.default.inc";
include_once "common.inc";
include_once "simpleweb.inc";
include_once "openid.inc";
include_once "user.inc";
include_once "cache.inc";
include_once "filesystem.store.inc";

// Allow for PHP5 version of xtemplate
if (version_compare(PHP_VERSION, '5.0.0') === 1) {
    include "lib/xtemplate.class.php";
} else {
    include "lib/xtemplate-php4.class.php";
}

define('CACHE_DIR', SIMPLEID_CACHE_DIR);

define('PRE_0_7_0_VERSION', '0.6.0 or earlier');

/**
 * This variable holds the upgrade functions for each version of SimpleID
 *
 * @global array $upgrade_functions
 */
$upgrade_functions = array(
    '0.7.0' => array()
);


/**
 * This variable holds an instance of the XTemplate engine.
 *
 * @global object $xtpl
 */
$xtpl = NULL;

upgrade_start();

/**
 * Entry point for SimpleID.
 *
 * @see user_init()
 */
function upgrade_start() {
    global $xtpl;
        
    $xtpl = new XTemplate('html/upgrade.xtpl');
    $xtpl->assign('version', SIMPLEID_VERSION);
    
    // Check if the configuration file has been defined
    if (!defined('SIMPLEID_BASE_URL')) {
        set_message('No configuration file found.  See the <a href="http://simpleid.sourceforge.net/documentation/getting-started">manual</a> for instructions on how to set up a configuration file.');
        $xtpl->parse('main');
        $xtpl->out('main');
        exit;
    }
    
    if (!is_dir(SIMPLEID_IDENTITIES_DIR)) {
        set_message('Identities directory not found.  See the <a href="http://simpleid.sourceforge.net/documentation/getting-started">manual</a> for instructions on how to set up SimpleID.');
        $xtpl->parse('main');
        $xtpl->out('main');
        exit;
    }
    
    if (!is_dir(SIMPLEID_CACHE_DIR) || !is_writeable(SIMPLEID_CACHE_DIR)) {
        set_message('Cache directory not found or not writeable.  See the <a href="http://simpleid.sourceforge.net/documentation/getting-started">manual</a> for instructions on how to set up SimpleID.');
        $xtpl->parse('main');
        $xtpl->out('main');
        exit;
    }
    
    
    if (!is_dir(SIMPLEID_STORE_DIR) || !is_writeable(SIMPLEID_STORE_DIR)) {
        set_message('Store directory not found or not writeable.  See the <a href="http://simpleid.sourceforge.net/documentation/getting-started">manual</a> for instructions on how to set up SimpleID.');
        $xtpl->parse('main');
        $xtpl->out('main');
        exit;
    }
    
    $q = (isset($_REQUEST['q'])) ? $_REQUEST['q'] : '';
    $q = explode('/', $q);
    
    extension_init();
    user_init(NULL);
    upgrade_user_init();
    
    $routes = array(
        'upgrade-selection' => 'upgrade_selection',
        'upgrade-apply' => 'upgrade_apply',
        '.*' => 'upgrade_info'
    );
    
    simpleweb_run($routes, implode('/', $q));
}

function upgrade_info() {
    global $xtpl;
    
    $xtpl->assign('token', get_form_token('upgrade_info'));
    $xtpl->parse('main.info');
    
    $xtpl->assign('title', 'Upgrade');
    $xtpl->parse('main');
    
    $xtpl->out('main');
}

function upgrade_selection() {
    global $xtpl, $upgrade_access_check;
    
    cache_gc(0, 'upgrade');
    
    if (!validate_form_token($_POST['tk'], 'upgrade_info')) {
        set_message('SimpleID detected a potential security attack.  Please try again.');
        upgrade_info();
        return;
    }

    $functions = upgrade_get_functions();
    
    if (count($functions) == 0) {
        if (!$upgrade_access_check) $xtpl->parse('main.selection.selection_complete.upgrade_access_check');
        $xtpl->parse('main.selection.selection_complete');
    } else {
        $handle = openid_handle();
        cache_set('upgrade', $handle, $functions);
        
        $xtpl->assign('handle', $handle);
        $xtpl->assign('token', get_form_token('upgrade_selection'));
        $xtpl->parse('main.selection.selection_continue');
    }
    
    $xtpl->assign('original_version', upgrade_get_version());
    $xtpl->assign('this_version', SIMPLEID_VERSION);
    $xtpl->parse('main.selection');
    
    $xtpl->assign('title', 'Upgrade');
    $xtpl->parse('main');
    
    $xtpl->out('main');
}

function upgrade_apply() {
    global $xtpl, $upgrade_access_check;
    
    if (!validate_form_token($_POST['tk'], 'upgrade_selection')) {
        set_message('SimpleID detected a potential security attack.  Please try again.');
        upgrade_selection();
        return;
    }
    
    $functions = cache_get('upgrade', $_POST['handle']);
    
    foreach ($functions as $function) {
        call_user_func($function);
    }
    
    if (!$upgrade_access_check) $xtpl->parse('main.results.upgrade_access_check');
    $xtpl->parse('main.results');
    
    cache_gc(0, 'upgrade');
    
    $xtpl->assign('title', 'Upgrade');
    $xtpl->parse('main');
    
    $xtpl->out('main');
}

function upgrade_get_version() {
    return store_get('version', '0.6.0 or earlier');
}

function upgrade_set_version($version = NULL) {
    if ($version == NULL) $version = SIMPLEID_VERSION;
    store_set('version', $version);
}

function upgrade_get_functions($version = NULL) {
    global $upgrade_functions;
    
    if ($version == NULL) $version = upgrade_get_version();
    $functions = array();
    
    uksort($upgrade_functions, '_upgrade_version_reverse_sort');
    
    foreach ($upgrade_functions as $upgrade_version => $upgrades) {
        if (version_compare($version, $upgrade_version, '<')) {
            $functions = array_merge($functions, $upgrades);
        }
    }
    
    if (version_compare($version, SIMPLEID_VERSION, '<')) $functions[] = 'upgrade_set_version';
    
    return $functions;
}

function _upgrade_version_reverse_sort($a, $b) {
    return -version_compare($a, $b);
}

function upgrade_user_init() {
    global $user, $upgrade_access_check;
    
    if ($upgrade_access_check) {
        if (($user == NULL) || ($user['administrator'] != 1)) upgrade_access_denied();
    }
}

function upgrade_access_denied() {
    global $xtpl;
    
    $xtpl->parse('main.access_denied');
    
    $xtpl->assign('title', 'Access Denied');
    $xtpl->parse('main');
    
    $xtpl->out('main');
    exit;
}

function upgrade_rp_to_store() {
    // For each user, do cache_get('rp', $uid), move to $user, then store_user_save()
    
    $dir = opendir(SIMPLEID_IDENTITIES_DIR);
    
    while (($file = readdir($dir)) !== false) {
        $filename = SIMPLEID_IDENTITIES_DIR . '/' . $file;
        
        if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.identity$/', $file, $matches))) continue;
        
        $uid = $matches[1];
        
        $user = user_load($uid);
        $rp = cache_get('rp', $uid);
        $user['rp'] = $rp;
        user_save($user);
    }
}

?>
