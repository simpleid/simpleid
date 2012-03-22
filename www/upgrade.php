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

/**
 * SimpleID upgrade script.
 *
 * This script performs various upgrades to SimpleID's storage backend, which
 * are required for different versions of SimpleID.
 *
 * @package simpleid
 * @since 0.7
 * @filesource
 */

/**
 * Access control for this script.
 *
 * If you are upgrading your SimpleID installation using the upgrade.php script,
 * and you are not logged in as an administrator, you will need to modify the access
 * check statement below.
 *
 * Change the TRUE to a FALSE to disable the access
 * check. After finishing the upgrade, be sure to open this file again
 * and change the FALSE back to a TRUE.
 *
 * @global bool $upgrade_access_check
 */
$upgrade_access_check = TRUE;

/* ----- Do not modify anything following this line ------------------------- */

include_once "version.inc.php";
if (file_exists("config.php")) {
    include_once "config.php";
} elseif (file_exists("config.inc")) {
    include_once "config.inc";
    define('UPGRADE_LEGACY_CONFIG_INC', TRUE);
}
include_once "config.default.php";
include_once "log.inc.php";
include_once "locale.inc.php";
include_once "common.inc.php";
include_once "simpleweb.inc.php";
include_once "openid.inc.php";
include_once "user.inc.php";
include_once "cache.inc.php";
include_once SIMPLEID_STORE . ".store.php";
include "lib/xtemplate.class.php";

define('CACHE_DIR', SIMPLEID_CACHE_DIR);

define('PRE_0_7_0_VERSION', '0.6.0 or earlier');

/**
 * This variable holds the upgrade functions for each version of SimpleID
 *
 * @global array $upgrade_functions
 */
$upgrade_functions = array(
    '0.9.0' => array('upgrade_config_inc_to_php'),
    '0.7.0' => array('upgrade_rp_to_store', 'upgrade_token_to_store')
);


/**
 * This variable holds an instance of the XTemplate engine.
 *
 * @global object $xtpl
 */
$xtpl = NULL;

/**
 * This variable holds the combined $_GET and $_POST superglobal arrays.
 * This is then passed through {@link openid_fix_request()}.
 *
 * @global array $GETPOST
 */
$GETPOST = array_merge($_GET, $_POST);

upgrade_start();

/**
 * Entry point for SimpleID upgrade script.
 *
 * @see user_init()
 */
function upgrade_start() {
    global $xtpl, $GETPOST;
    
    locale_init(SIMPLEID_LOCALE);
        
    $xtpl = new XTemplate('html/template.xtpl');
    $xtpl->assign('version', SIMPLEID_VERSION);
    $xtpl->assign('base_path', get_base_path());
    $xtpl->assign('css', '@import url(' . get_base_path() . 'html/upgrade.css);');
    $xtpl->assign('footer_doc', t('Documentation'));
    $xtpl->assign('footer_support', t('Support'));
    
    // Check if the configuration file has been defined
    if (!defined('SIMPLEID_BASE_URL')) {
        indirect_fatal_error(t('No configuration file found.  See the <a href="!url">manual</a> for instructions on how to set up a configuration file.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started')));
    }
    
    if (!is_dir(SIMPLEID_IDENTITIES_DIR)) {
        indirect_fatal_error(t('Identities directory not found.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started')));
    }
    
    if (!is_dir(SIMPLEID_CACHE_DIR) || !is_writeable(SIMPLEID_CACHE_DIR)) {
        indirect_fatal_error(t('Cache directory not found or not writeable.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started')));
    }
    
    if (!is_dir(SIMPLEID_STORE_DIR) || !is_writeable(SIMPLEID_STORE_DIR)) {
        indirect_fatal_error(t('Store directory not found or not writeable.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started')));
    }

    if ((@ini_get('register_globals') === 1) || (@ini_get('register_globals') === '1') || (strtolower(@ini_get('register_globals')) == 'on')) {
        indirect_fatal_error(t('register_globals is enabled in PHP configuration, which is not supported by SimpleID.  See the <a href="!url">manual</a> for further information.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/system-requirements')));
    }
    
    if (!bignum_loaded()) {
        log_fatal('gmp/bcmath PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'gmp/bcmath', '!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/system-requirements')));
    }
    if (!function_exists('preg_match')) {
        log_fatal('pcre PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'pcre', '!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/system-requirements')));
    }
    if (!function_exists('session_start')) {
        log_fatal('session PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'session', '!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/system-requirements')));
    }
    if (!function_exists('xml_parser_create_ns')) {
        log_fatal('xml PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'xml', '!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/system-requirements')));
    }
    if (!function_exists('hash')) {
        log_fatal('hash PHP extension not loaded.');
        indirect_fatal_error(t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'hash', '!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/system-requirements')));
    }


    $q = (isset($GETPOST['q'])) ? $GETPOST['q'] : '';
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

/**
 * Displays the upgrade info page.
 */
function upgrade_info() {
    global $xtpl;
    
    $xtpl->assign('token', get_form_token('upgrade_info'));
    
    $xtpl->assign('intro', t('Use this script to update your installation whenever you upgrade to a new version of SimpleID.'));
    $xtpl->assign('simpleid_docs', t('For more detailed information, see the <a href="!url">SimpleID documentation</a>.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/upgrading')));
    $xtpl->assign('step1', t('<strong>Back up your installation</strong>. This process will change various files within your SimpleID installation and in case of emergency you may need to revert to a backup.'));
    $xtpl->assign('step2', t('Install your new files in the appropriate location, as described in the <a href="!url">SimpleID documentation</a>.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/installing-simpleid')));
    $xtpl->assign('click_continue', t('When you have performed the steps above, click <strong>Continue</strong>.'));
    $xtpl->assign('continue_button', t('Continue'));
    
    $xtpl->parse('main.upgrade_info');
    
    $xtpl->assign('title', t('Upgrade'));
    $xtpl->parse('main');
    
    $xtpl->out('main');
}

/**
 * Detects the current installed version of SimpleID, selects the individual upgrade
 * functions applicable to this upgrade and displays the upgrade
 * selection page.
 */
function upgrade_selection() {
    global $xtpl, $upgrade_access_check;
    
    cache_expire(array('upgrade' => 0));
    
    if (!validate_form_token($_POST['tk'], 'upgrade_info')) {
        set_message(t('SimpleID detected a potential security attack.  Please try again.'));
        upgrade_info();
        return;
    }

    $functions = upgrade_get_functions();
    
    if (count($functions) == 0) {
        if (!$upgrade_access_check) {
            $xtpl->assign('edit_upgrade_php', t('Remember to edit upgrade.php to check <code>$upgrade_access_check</code> back to <code>FALSE</code>.'));
            $xtpl->parse('main.selection.selection_complete.upgrade_access_check');
        }
        
        $xtpl->assign('script_complete', t('Your SimpleID installation is up-to-date.  This script is complete.'));
        
        $xtpl->parse('main.upgrade_selection.selection_complete');
    } else {
        $handle = random_id();
        cache_set('upgrade', $handle, $functions);
        
        $xtpl->assign('handle', $handle);
        $xtpl->assign('token', get_form_token('upgrade_selection'));
        
        $xtpl->assign('click_continue', t('Click <strong>Continue</strong> to proceed with the upgrade.'));
        $xtpl->assign('continue_button', t('Continue'));
        
        $xtpl->parse('main.upgrade_selection.selection_continue');
    }
    
    $xtpl->assign('original_version', upgrade_get_version());
    $xtpl->assign('this_version', SIMPLEID_VERSION);
    
    $xtpl->assign('version_detected', t('The version of SimpleID you are updating from has been automatically detected.'));
    $xtpl->assign('original_version_label', t('Original version'));
    $xtpl->assign('this_version_label', t('Upgrade version'));
    
    $xtpl->parse('main.upgrade_selection');
    
    $xtpl->assign('title', t('Upgrade'));
    $xtpl->parse('main');
    
    $xtpl->out('main');
}

/**
 * Applies the upgrade.
 */
function upgrade_apply() {
    global $xtpl, $upgrade_access_check;
    
    if (!validate_form_token($_POST['tk'], 'upgrade_selection')) {
        set_message(t('SimpleID detected a potential security attack.  Please try again.'));
        upgrade_selection();
        return;
    }
    
    $results = '';
    $functions = cache_get('upgrade', $_POST['handle']);
    
    foreach ($functions as $function) {
        $results .= call_user_func($function);
    }
    
    if (!$upgrade_access_check) {
        $xtpl->assign('edit_upgrade_php', t('Remember to edit upgrade.php to check <code>$upgrade_access_check</code> back to <code>FALSE</code>.'));
        $xtpl->parse('main.upgrade_results.upgrade_access_check');
    }
    $xtpl->assign('results', $results);
    
    $xtpl->assign('upgrade_complete', t('Your SimpleID installation has been upgraded.  Please check the results below for any errors.'));
    
    $xtpl->parse('main.upgrade_results');
    
    cache_expire(array('upgrade' => 0));
    
    $xtpl->assign('title', t('Upgrade'));
    $xtpl->parse('main');
    
    $xtpl->out('main');
}

/**
 * Detects the current installed version of SimpleID
 *
 * The current installed version of SimpleID is taken from the {@link store_get() version}
 * application setting.  This setting is only available for versions 0.7 or later, so
 * if it is absent we can assume it's prior to version 0.7.
 *
 * @return string the detected version, or the string '0.6.0 or earlier'
 */
function upgrade_get_version() {
    return store_get('version', '0.6.0 or earlier');
}

/**
 * Sets the current version of SimpleID.
 *
 * This function sets the version application setting via {@link store_get()}.
 * A specific version can be specified, or it can be taken from {@link SIMPLEID_VERSION}.
 *
 * @param string $version the version to set
 */
function upgrade_set_version($version = NULL) {
    if ($version == NULL) $version = SIMPLEID_VERSION;
    store_set('version', $version);
}

/**
 * Selects the upgrade functions applicable for this upgrade.
 *
 * The upgrade functions are specified by the {@link $upgrade_functions}
 * variable.  This variable is an associative array containing version numbers
 * as keys and an array of upgrade function names as values.  This function
 * merges all the upgrade function names of the version between the current
 * installed version and the upgraded version.
 *
 * @param string $version the version of SimpleID to upgrade from, calls
 * {@link upgrade_get_version()} if not specified
 * @return array an array of strings, containing the list of upgrade functions
 * to call.  The functions should be called in the same order as they appear
 * in this array
 *
 */
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

/**
 * Callback function for uksort() to reverse sort version numbers.
 *
 * @param string $a
 * @param string $b
 * @return int
 */
function _upgrade_version_reverse_sort($a, $b) {
    return -version_compare($a, $b);
}

/**
 * Determines whether the current user has permission to run this script.
 *
 * A user has permission to run this script if:
 *
 * - administrator=1 appears in the user's identity file; or
 * - {@link $upgrade_access_check} is false
 *
 * If the user does not have permission, {@link upgade_access_denied()} is called
 */
function upgrade_user_init() {
    global $user, $upgrade_access_check;
    
    if ($upgrade_access_check) {
        if (($user == NULL) || ($user['administrator'] != 1)) upgrade_access_denied();
    }
}

/**
 * Displays a page notifying the user that he or she does not have permission to
 * run the upgrade script.
 */
function upgrade_access_denied() {
    global $xtpl;
    
    $xtpl->assign('login_required', t('Access denied. You are not authorised to access this page. Please <a href="index.php?q=login">log in</a> as an administrator (a user whose identity file includes the line <code>administrator=1</code>).'));    
    $xtpl->assign('edit_upgrade_php', t('If you cannot log in, you will have to edit <code>upgrade.php</code> to bypass this access check. To do this:'));
    $xtpl->assign('edit_upgrade_php1', t('With a text editor find the upgrade.php file.'));
    $xtpl->assign('edit_upgrade_php2', t('There is a line inside your upgrade.php file that says <code>$upgrade_access_check = TRUE;</code>. Change it to <code>$upgrade_access_check = FALSE;</code>.'));
    $xtpl->assign('edit_upgrade_php3', t('As soon as the upgrade.php script is done, you must change the file back to its original form with <code>$upgrade_access_check = TRUE;</code>.'));
    $xtpl->assign('edit_upgrade_php4', t('To avoid having this problem in future, remember to log in to SimpleID as an administrator before you run this script.'));
    $xtpl->assign('simpleid_docs', t('For more detailed information, see the <a href="!url">SimpleID documentation</a>.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/upgrading/running-upgradephp')));
    
    $xtpl->parse('main.upgrade_access_denied');
    
    $xtpl->assign('title', t('Access Denied'));
    $xtpl->parse('main');
    
    $xtpl->out('main');
    exit;
}

/* ------------------------------------------------------------------------------------------------------- */

/**
 * Moves the user's site preferences from the cache to the store.
 *
 * @since 0.7
 */
function upgrade_rp_to_store() {
    $dir = opendir(SIMPLEID_IDENTITIES_DIR);
    
    while (($file = readdir($dir)) !== false) {
        $filename = SIMPLEID_IDENTITIES_DIR . '/' . $file;
        
        if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.identity$/', $file, $matches))) continue;
        
        $uid = $matches[1];
        
        $user = user_load($uid);
        $rp = cache_get('rp', $uid);
        if ($rp != NULL) {
            $user['rp'] = $rp;
            user_save($user);
            cache_delete('rp', $uid);
        }
    }
}

/**
 * Moves the site token from the cache to the store.
 *
 * @since 0.7
 */
function upgrade_token_to_store() {
    $site_token = cache_get('token', SIMPLEID_BASE_URL);
    
    if ($site_token != NULL) {
        store_set('site-token', $site_token);
        cache_delete('token', SIMPLEID_BASE_URL);
    }
}

/**
 * Checks that config.inc has been renamed to config.php
 *
 * @since 0.9
 */
function upgrade_config_inc_to_php() {
    if (defined('UPGRADE_LEGACY_CONFIG_INC')) {
        return '<p>You will need to rename <code>config.inc</code> to <code>config.php</code>.</p>';
    }
}
?>
