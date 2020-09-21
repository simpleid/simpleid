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
include_once 'version.inc.php';
$class_loader = include_once('autoload.inc.php');

// 1. Constants
const SIMPLEID_INSTANT_TOKEN_EXPIRES_IN = 60;
const SIMPLEID_SHORT_TOKEN_EXPIRES_IN = 3600;
const SIMPLEID_HUMAN_TOKEN_EXPIRES_IN = 43200;
const SIMPLEID_LONG_TOKEN_EXPIRES_IN = 1209600;
const SIMPLEID_LONG_TOKEN_EXPIRES_BUFFER = 300;
const SIMPLEID_ETERNAL_TOKEN_EXPIRES_IN = 315360000;


// 2. Load configuration
$default_config = array(
    'allow_plaintext' => false,
    'allow_autocomplete' => false,
    'openid_verify_return_url' => true,
    'openid_strict_realm_check' => true,
    'webfinger_access_control_allow_origin' => '*',
    'locale' => 'en',
    'logger' => 'SimpleID\Util\DefaultLogger',
    'log_file' => '',
    'log_level' => 'info',
    'date_time_format' => '%Y-%m-%d %H:%M:%S %Z',
    'acr' => 1,
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
        'SimpleID\Protocols\OpenID\Extensions\SRegOpenIDExtensionModule',
        'SimpleID\Protocols\WebFinger\WebFingerModule',
    ),
);

// Check if the configuration file has been defined
if (file_exists('conf/config.php')) {
    $config = include_once('conf/config.php');
} elseif (file_exists('config.php')) {
    $config = include_once('config.php');
} else {
    die('No configuration file found.  See <http://simpleid.org/docs/2/installing/> for instructions on how to set up a configuration file.');
}


$f3 = \Base::instance();

$config = array_replace_recursive($default_config, $config);
if (!isset($config['canonical_base_path'])) {
    $port = $f3->get('PORT');
    $config['canonical_base_path'] = $f3->get('SCHEME') .'://'. $_SERVER['SERVER_NAME']
        . ($port && $port != 80 && $port != 443 ? (':' . $port) : '') . $f3->get('BASE');
}

if (function_exists('date_default_timezone_set')) date_default_timezone_set(@date_default_timezone_get());

$f3->mset(array(
    'CASELESS' => false,
    'CORS.origin' => '*',
    'JAR.domain' => '',
    'JAR.secure' => false,
    'PACKAGE' => 'SimpleID/' . SIMPLEID_VERSION,
    'TEMP' => $config['temp_dir'] . '/',
    'UI' => 'html/'
));
$f3->set('version', SIMPLEID_VERSION);
$f3->set('base_path', $f3->get('BASE') . '/');
$f3->set('config', $config);
$f3->set('class_loader', $class_loader);

// 3. Temp directory
if (!is_dir($f3->get('TEMP')) || !is_writable($f3->get('TEMP'))) {
    die('Temp directory not found or not writeable.  Make sure temp_dir is set up properly in config.php.');
}

// 4. Cache
if (preg_match('/^folder\h*=\h*(.+)/', $config['cache']) && substr($config['cache'], -1) != '/') {
    $config['cache'] .= '/';
}
$f3->set('CACHE', $config['cache']);
$cache = \Cache::instance();
//$cache->reset(null, SIMPLEID_LONG_TOKEN_EXPIRES_IN);

// 5. Logging
if (!isset($config['logger']) || ($config['logger'] == '') || ($config['log_file'] == '')) {
    $config['logger'] = 'Psr\Log\NullLogger';
}
if (is_subclass_of($config['logger'], '\Log', true)) $f3->set('LOGS', dirname($config['log_file']) . '/');
$logger = new $config['logger']($config);
$f3->set('logger', $logger);

if (isset($config['f3_DEBUG'])) $f3->set('DEBUG', $config['f3_DEBUG']);

// 6. Fix up HTTP request
fix_http_request($f3);

// For SimpleID 1.x compatibility
if (isset($_GET['q'])) {
    $f3->set('PATH', '/' . $_GET['q']);
    unset($_GET['q']);
}

// 7. Check for other configuration errors
$i18n = \SimpleID\Util\LocaleManager::instance();

if ((@ini_get('register_globals') === 1) || (@ini_get('register_globals') === '1') || (strtolower(@ini_get('register_globals')) == 'on')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'register_globals is enabled in PHP configuration.');
    $f3->error(500, $i18n->t('register_globals is enabled in PHP configuration, which is not supported by SimpleID.  See the <a href="!url">manual</a> for further information.', array('!url' => 'http://simpleid.org/docs/2/system-requirements/')));
}

if (!\SimpleID\Crypt\BigNum::loaded()) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'gmp/bcmath PHP extension not loaded.');
    $f3->error(500, $i18n->t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'gmp/bcmath', '!url' => 'http://simpleid.org/docs/2/system-requirements/')));
}
if (!function_exists('preg_match')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'pcre PHP extension not loaded.');
    $f3->error(500, $i18n->t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'pcre', '!url' => 'http://simpleid.org/docs/2/system-requirements/')));
}
if (!function_exists('session_start')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'session PHP extension not loaded.');
    $f3->error(500, $i18n->t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'session', '!url' => 'http://simpleid.org/docs/2/system-requirements/')));
}
if (!function_exists('xml_parser_create_ns')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'xml PHP extension not loaded.');
    $f3->error(500, $i18n->t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'xml', '!url' => 'http://simpleid.org/docs/2/system-requirements/')));
}
if (!function_exists('hash')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'hash PHP extension not loaded.');
    $f3->error(500, $i18n->t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'hash', '!url' => 'http://simpleid.org/docs/2/system-requirements/')));
}
if (!function_exists('openssl_sign')) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'openssl PHP extension not loaded.');
    $f3->error(500, $i18n->t('One or more required PHP extensions (%extension) is not loaded.  See the <a href="!url">manual</a> for further information on system requirements.', array('%extension' => 'openssl', '!url' => 'http://simpleid.org/docs/2/system-requirements/')));
}
if (is_numeric(@ini_get('suhosin.get.max_value_length')) && (@ini_get('suhosin.get.max_value_length') < 1024)) {
    $f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'suhosin.get.max_value_length < 1024');
    $f3->error(500, $i18n->t('suhosin.get.max_value_length is less than 1024, which will lead to problems. See the <a href="!url">manual</a> for further information on system requirements.', array('!url' => 'http://simpleid.org/docs/2/system-requirements/')));
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