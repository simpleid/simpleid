<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2023
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

namespace SimpleID;

use SimpleID\Auth\AuthManager;
use SimpleID\Util\UI\Template;

/**
 * A SimpleID module.
 *
 * A module represents a single unit of functionality in SimpleID.
 * Apart from a small number of required modules, modules can be enabled
 * or disabled via the configuration file.
 *
 * A SimpleID module is a singleton class under the FatFree Framework.
 * This class is the superclass of all SimpleID modules.  This class
 * also provides a number of common functions which are used by
 * all modules.
 */
abstract class Module extends \Prefab {
    /** FatFree framework object
     * @var \Base
     */
    protected $f3;

    /** Logger
     * @var \Psr\Log\LoggerInterface 
     */
    protected $logger;

    /**
     * Initialises the module.
     * 
     * This static method is called during initialisation.  Subclasses can
     * use this to, among other things:
     * 
     * - register URL routes with the Fat-Free Framework using `$f3->route()`
     *   or `$f3->map()`
     * - register events
     *
     * @param \Base $f3 the FatFree framework
     * @return void
     */
    public static function init($f3) {

    }

    /**
     * Creates a module.
     *
     * This default constructor performs the following:
     *
     * - sets the {@link $logger} variable to the current logger
     * - sets the locale domain
     */
    public function __construct() {
        $this->f3 = \Base::instance();
        $this->logger = $this->f3->get('logger');

        $mgr = ModuleManager::instance();
        $info = $mgr->getModuleInfo(get_class($this));
    }

    /**
     * FatFree Framework event handler.
     *
     * This event handler initialises the user system.  It starts the PHP session
     * and loads data for the currently logged-in user, if any.
     *
     * @return void
     */
    public function beforeroute() {
        $auth = AuthManager::instance();
        $auth->initSession();
        $auth->initUser();
    }

    /**
     * Determines whether the current connection with the user agent is via
     * HTTPS.
     *
     * HTTPS is detected if one of the following occurs:
     *
     * - $_SERVER['HTTPS'] is set to 'on' (Apache installations)
     * - $_SERVER['HTTP_X_FORWARDED_PROTO'] is set to 'https' (reverse proxies)
     * - $_SERVER['HTTP_FRONT_END_HTTPS'] is set to 'on'
     *
     * @return bool true if the connection is via HTTPS
     */
    protected function isHttps() {
        return ($this->f3->get('SCHEME') == 'https')
            || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && (strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) == 'https'))
            || (isset($_SERVER['HTTP_FRONT_END_HTTPS']) && ($_SERVER['HTTP_FRONT_END_HTTPS'] == 'on'));
    }


    /**
     * Ensure the current connection with the user agent is secure with HTTPS.
     *
     * This function uses {@link isHttps()} to determine whether the connection
     * is via HTTPS.  If it is, this function will return successfully.
     *
     * If it is not, what happens next is determined by the following steps.
     *
     * 1. If $allow_override is true and allow_plaintext is also true,
     * then the function will return successfully
     * 2. Otherwise, then it will either redirect (if $action is
     * redirect) or return an error (if $action is error)
     *
     * @param string $action what to do if connection is not secure - either
     * 'redirect' or 'error'
     * @param boolean $allow_override whether allow_plaintext is checked
     * to see if an unencrypted connection is allowed
     * @param string $redirect_url if $action is redirect, what URL to redirect to.
     * If null, this will redirect to the same page (albeit with an HTTPS connection)
     * @param boolean $strict whether HTTP Strict Transport Security is active   
     * @return void  
     */
    protected function checkHttps($action = 'redirect', $allow_override = false, $redirect_url = null, $strict = true) {
        if ($this->isHttps()) {
            if ($strict) header('Strict-Transport-Security: max-age=3600');
            return;
        }

        $config = $this->f3->get('config');
        
        if ($allow_override && $config['allow_plaintext']) return;
        
        if ($action == 'error') {
            $this->f3->status(426);

            header('Upgrade: TLS/1.2, HTTP/1.1');
            header('Connection: Upgrade');
            $this->fatalError($this->f3->get('intl.common.require_https'));
            exit;
        }
        
        if ($redirect_url == null) $redirect_url = $this->getCanonicalURL($this->f3->get('PATH'), $this->f3->get('SERVER.QUERY_STRING'), 'https');
        
        $this->f3->status(301);
        header('Location: ' . $redirect_url);
        exit;
    }

    /**
     * Obtains a SimpleID URL.  URLs produced by SimpleID should use this function.
     *
     * @param string $path the FatFree path or alias
     * @param string $query a properly encoded query string
     * @param string $secure if $relative is false, either 'https' to force an HTTPS connection, 'http' to force
     * an unencrypted HTTP connection, 'detect' to base on the current connection, or NULL to vary based on the
     * `canonical_base_path` configuration
     * @return string the url
     *
     * @since 0.7
     */
    public function getCanonicalURL($path = '', $query = '', $secure = null) {
        $config = $this->f3->get('config');
        $canonical_base_path = $config['canonical_base_path'];

        if (preg_match('/^(?:@(\w+)(?:(\(.+?)\))*|https?:\/\/)/', $path, $parts)) {
            if (isset($parts[1])) {
                $aliases = $this->f3->get('ALIASES');

                if (!empty($aliases[$parts[1]])) {
                    $path = $aliases[$parts[1]];
                    $path = $this->f3->build($path, isset($parts[2]) ? $this->f3->parse($parts[2]) : []);
                    $path = ltrim($path, '/');
                }
            }
        }
        
        // Make sure that the base has a trailing slash
        if ((substr($config['canonical_base_path'], -1) == '/')) {
            $url = $config['canonical_base_path'];
        } else {
            $url = $config['canonical_base_path'] . '/';
        }
        
        if (($secure == 'https') && (stripos($url, 'http:') === 0)) {
            $url = 'https:' . substr($url, 5);
        }
        if (($secure == 'http') && (stripos($url, 'https:') === 0)) {
            $url = 'http:' . substr($url, 6);
        }
        if (($secure == 'detect') && ($this->isHttps()) && (stripos($url, 'http:') === 0)) {
            $url = 'https:' . substr($url, 5);
        }
        if (($secure == 'detect') && (!$this->isHttps()) && (stripos($url, 'https:') === 0)) {
            $url = 'http:' . substr($url, 6);
        }
        
        $url .= $path . (($query == '') ? '' : '?' . $query);
        
        return $url;
    }

    /**
     * Displays a fatal error message and exits.
     *
     * @param string $error the message to set
     * @param int $code the HTTP status code to send
     * @return void
     */
    protected function fatalError(string $error, int $code = 500) {
        // This also sends the HTTP status code
        $title = $this->f3->status($code);
        $this->f3->expire(-1);
        $trace = $this->f3->trace();

        $this->f3->set('error', $error);
        if ($this->f3->get('DEBUG') > 0) $this->f3->set('trace', $trace);

        $this->f3->set('page_class', 'is-dialog-page');
        $this->f3->set('title', $title);
        $this->f3->set('layout', 'fatal_error.html');

        $tpl = Template::instance();
        print $tpl->render('page.html');
        exit;
    }

    /**
     * Compares two strings using the same time whether they're equal or not.
     * This function should be used to mitigate timing attacks when, for
     * example, comparing password hashes
     *
     * @param string $str1
     * @param string $str2
     * @return bool true if the two strings are equal
     */
    public function secureCompare($str1, $str2) {
        if (function_exists('hash_equals')) return hash_equals($str1, $str2);

        $xor = $str1 ^ $str2;
        $result = strlen($str1) ^ strlen($str2); //not the same length, then fail ($result != 0)
        for ($i = strlen($xor) - 1; $i >= 0; $i--) $result += ord($xor[$i]);
        return !$result;
    }
}

?>