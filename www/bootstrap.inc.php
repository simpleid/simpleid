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
include_once 'autoload.inc.php';
include_once 'version.inc.php';

// 2. Configuration
const SIMPLEID_INSTANT_TOKEN_EXPIRES_IN = 60;
const SIMPLEID_SHORT_TOKEN_EXPIRES_IN = 3600;
const SIMPLEID_HUMAN_TOKEN_EXPIRES_IN = 43200;
const SIMPLEID_LONG_TOKEN_EXPIRES_IN = 1209600;
const SIMPLEID_LONG_TOKEN_EXPIRES_BUFFER = 300;
const SIMPLEID_ETERNAL_TOKEN_EXPIRES_IN = 315360000;

// TODO: log_callback causes issues with PHPUnit
$default_config = array(
    'allow_plaintext' => false,
    'allow_autocomplete' => false,
    'openid_verify_return_url' => true,
    'webfinger_rate_limit' => 1,
    'webfinger_access_control_allow_origin' => '*',
    'locale' => 'en',
    'log_callback' => function() {
        $f3 = \Base::instance();
        $config = $f3->get('config');
        if ($config['log_file'] == '') return new \Psr\Log\NullLogger();

        $f3->set('LOGS', dirname($config['log_file']) . '/');
        return new \SimpleID\Util\DefaultLogger(basename($config['log_file']), $config['log_level']);
    },
    'log_file' => '',
    'log_level' => 'info',
    'date_time_format' => '%Y-%m-%d %H:%M:%S %Z',
    'required_modules' => array(
        'SimpleID\Base\IndexModule',
        'SimpleID\Store\DefaultStoreModule',
        'SimpleID\Auth\AuthModule',
        'SimpleID\Base\UserModule',
    ),
    'modules' => array(
        'SimpleID\Base\MyModule',
        'SimpleID\Auth\PasswordAuthSchemeModule',
        'SimpleID\Auth\RememberMeAuthSchemeModule',
        'SimpleID\Auth\OTPAuthSchemeModule',
        'SimpleID\Protocols\OpenID\OpenIDModule',
        'SimpleID\Protocols\WebFinger\WebFingerModule',
    ),
    'ext_modules' => array()
);

include_once 'config.php';

$config = array_merge($default_config, $config);
if (!isset($config['canonical_base_path'])) {
    // TODO
}

if (function_exists('date_default_timezone_set')) date_default_timezone_set(@date_default_timezone_get());

$f3 = \Base::instance();
$f3->mset(array(
    'CASELESS' => false,
    'JAR.domain' => '',
    'JAR.secure' => false,
    'PACKAGE' => 'SimpleID/' . SIMPLEID_VERSION,
    'TEMP' => getenv('TEMP') . '/',
    'UI' => 'html/'
));
$f3->set('version', SIMPLEID_VERSION);
$f3->set('base_path', $f3->get('BASE') . '/');
$f3->set('config', $config);

// Cache
if (preg_match('/^folder\h*=\h*(.+)/', $config['cache']) && substr($config['cache'], -1) != '/') {
    $config['cache'] .= '/';
}
$f3->set('CACHE', $config['cache']);
$cache = \Cache::instance();
$cache->reset(null, SIMPLEID_LONG_TOKEN_EXPIRES_IN);

// Logging
$f3->set('logger', $config['log_callback']());

$f3->set('DEBUG', 4);

// HTTP
fix_http_request($f3);

// For SimpleID 1.x compatibility
if (isset($_GET['q'])) {
    $f3->set('PATH', $_GET['q']);
    unset($_GET['q']);
}

// 3. Check for configuration errors
/*if (!is_dir(SIMPLEID_IDENTITIES_DIR)) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'Identities directory not found.');
    $f3->error(500, t('Identities directory not found.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started')));
}

if (!is_dir(SIMPLEID_STORE_DIR) || !is_writeable(SIMPLEID_STORE_DIR)) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'Store directory not found or not writeable.');
    $f3->error(500, t('Store directory not found or not writeable.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started')));
}*/

if ((@ini_get('register_globals') === 1) || (@ini_get('register_globals') === '1') || (strtolower(@ini_get('register_globals')) == 'on')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'register_globals is enabled in PHP configuration.');
    $f3->error(500, t('register_globals is enabled in PHP configuration, which is not supported by SimpleID.  See the <a href="!url">manual</a> for further information.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
}

if (!\SimpleID\Crypt\BigNum::loaded()) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'gmp/bcmath PHP extension not loaded.');
    $f3->error(500, t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'gmp/bcmath', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
}
if (!function_exists('preg_match')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'pcre PHP extension not loaded.');
    $f3->error(500, t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'pcre', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
}
if (!function_exists('session_start')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'session PHP extension not loaded.');
    $f3->error(500, t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'session', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
}
if (!function_exists('xml_parser_create_ns')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'xml PHP extension not loaded.');
    $f3->error(500, t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'xml', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
}
if (!function_exists('hash')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'hash PHP extension not loaded.');
    $f3->error(500, t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'hash', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
}
if (!function_exists('openssl_sign')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'openssl PHP extension not loaded.');
    $f3->error(500, t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'openssl', '!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
}
if (is_numeric(@ini_get('suhosin.get.max_value_length')) && (@ini_get('suhosin.get.max_value_length') < 1024)) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'suhosin.get.max_value_length < 1024');
    $f3->error(500, t('suhosin.get.max_value_length is less than 1024, which will lead to problems. See the <a href="!url">manual</a> for further information on system requirements.', array('!url' => 'http://simpleid.koinic.net/documentation/getting-started/system-requirements')));
}

/* ------------------------------------------------------------------------- */

/**
 * Fix PHP's handling of request data.  PHP changes dots in all request parameters
 * to underscores when creating the $_GET, $_POST and $_REQUEST arrays.
 *
 * This function scans the original query string and POST parameters and fixes
 * them.
 */
function fix_http_request($f3) {
    // Fix GET parameters
    if (isset($_SERVER['QUERY_STRING'])) {
        $get = parse_http_query($_SERVER['QUERY_STRING']);
        
        foreach ($get as $key => $value) {
            // We strip out array-like identifiers - PHP uses special processing for these
            if ((strpos($key, '[') !== FALSE) && (strpos($key, ']') !== FALSE)) $key = substr($key, 0, strpos($key, '['));
            
            // Replace special characters with underscore as per PHP processing
            $php_key = preg_replace('/[ .[\x80-\x9F]/', '_', $key);
            
            // See if the PHP key is present; if so, copy and delete
            if (($key != $php_key) && isset($_GET[$php_key])) {
                $_GET[$key] = $_GET[$php_key];
                $_REQUEST[$key] = $_REQUEST[$php_key];
                unset($_GET[$php_key]);
                unset($_REQUEST[$php_key]);
            }
        }
    }
    
    // Fix POST parameters
    if ($f3->get('VERB') != 'POST') return;
    if ($f3->get('SERVER.CONTENT_TYPE') != 'application/x-www-form-urlencoded') return;

    $input = file_get_contents('php://input');
    if ($input !== FALSE) {
        $post = parse_http_query($input);
        
        foreach ($post as $key => $value) {
            // We strip out array-like identifiers - PHP uses special processing for these
            if ((strpos($key, '[') !== FALSE) && (strpos($key, ']') !== FALSE)) $key = substr($key, 0, strpos($key, '['));
            
            // Replace special characters with underscore as per PHP processing
            $php_key = preg_replace('/[ .[\x80-\x9F]/', '_', $key);
            
            // See if the PHP key is present; if so, copy and delete
            if (($key != $php_key) && isset($_POST[$php_key])) {
                $_POST[$key] = $_POST[$php_key];
                $_REQUEST[$key] = $_REQUEST[$php_key];
                unset($_POST[$php_key]);
                unset($_REQUEST[$php_key]);
            }
        }
    }
}

/**
 * Parses a query string.
 *
 * @param string $query the query string to parse
 * @return array an array containing the parsed key-value pairs
 *
 * @since 0.7
 */
function parse_http_query($query) {
    $data = array();
    
    if ($query === NULL) return array();
    if ($query === '') return array();
    
    $pairs = explode('&', $query);
    
    foreach ($pairs as $pair) {
        list ($key, $value) = explode('=', $pair, 2);
        $data[$key] = urldecode($value);
    }

    return $data;
}
?>