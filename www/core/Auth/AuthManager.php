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

namespace SimpleID\Auth;

use \Base;
use \Cache;
use \Prefab;
use Psr\Log\LogLevel;
use SimpleID\ModuleManager;
use SimpleID\Store\StoreManager;
use SimpleID\Crypt\Random;
use SimpleID\Util\OpaqueIdentifier;

/**
 * The authentication manager.
 */
class AuthManager extends Prefab {
    const AUTH_LEVEL_SESSION = 0;
    //const AUTH_LEVEL_AUTO_ONCE = 1;
    const AUTH_LEVEL_AUTO = 2;
    const AUTH_LEVEL_CREDENTIALS = 3;
    const AUTH_LEVEL_REENTER_CREDENTIALS = 4;
    const AUTH_LEVEL_VERIFIED = 5;

    const MODE_CREDENTIALS = self::AUTH_LEVEL_CREDENTIALS;
    const MODE_REENTER_CREDENTIALS = self::AUTH_LEVEL_REENTER_CREDENTIALS;
    const MODE_VERIFY = self::AUTH_LEVEL_VERIFIED;

    static private $cookie_prefix = null;

    protected $f3;
    protected $cache;
    protected $logger;
    protected $mgr;

    private $ua_login_state;

    public function __construct() {
        $this->f3 = Base::instance();
        $this->cache = Cache::instance();
        $this->logger = $this->f3->get('logger');
        $this->mgr = ModuleManager::instance();
    }

    /**
     * Initialises the PHP session system.
     */
    public function initSession() {
        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Auth\AuthManager->initSession');

        if (session_id() == '') {
            // session_name() has to be called before session_set_cookie_params()
            session_name($this->getCookieName('sess'));
            session_start();
        }
    }

    /**
     * Initialises the user system.  Loads data for the currently logged-in user,
     * if any.
     *
     * If there is no logged in user and $auto_auth is set to true, the system
     * queries the authentication scheme modules to determine whether a user can
     * be logged in automatically
     *
     * @param bool $auto_auth performs automatic authentication
     */
    public function initUser($auto_auth = true) {
        $this->logger->log(LogLevel::DEBUG, 'SimpleID\Auth\AuthManager->initUser');

        if (isset($_SESSION['auth']) && ($this->cache->get('user.' . rawurlencode($_SESSION['auth']['uid'])) == session_id())) {
            $store = StoreManager::instance();
            $user = $store->loadUser($_SESSION['auth']['uid']);
            $this->f3->set('user', $user);
        
            // If user has just been actively been authenticated in the previous request, then we
            // make it as actively authenticated in this request.
            $_SESSION['auth']['level'] = $_SESSION['auth']['next_level'];
            $_SESSION['auth']['next_level'] = self::AUTH_LEVEL_SESSION;
        } elseif ($auto_auth) {
            $modules = $this->mgr->getModules();

            foreach ($modules as $module) {
                $test_user = $this->mgr->invoke($module, 'autoAuth');
                if ($test_user != NULL) {
                    $this->login($test_user, self::AUTH_LEVEL_AUTO, array($module));
                    return;
                }
            }
        }
    }

    /**
     * Returns whether a user has logged in
     *
     * @return bool true if a user has logged in
     */
    public function isLoggedIn() {
        return ($this->f3->exists('user') === true);
    }

    /**
     * Returns the current logged in user
     *
     * @return User the current logged in user
     */
    public function getUser() {
        if ($this->isLoggedIn()) return $this->f3->get('user');
        return null;
    }

    /**
     * Returns the authentication level achieved for this session.
     *
     * @return int the authentication level
     */
    public function getAuthLevel() {
        return (isset($_SESSION['auth']) && isset($_SESSION['auth']['level'])) ? $_SESSION['auth']['level'] : null;
    }

    /**
     * Returns the time the user was authenticated (including via
     * automatic authentication).
     *
     * @return int the time
     */
    public function getAuthTime() {
        return (isset($_SESSION['auth']) && isset($_SESSION['auth']['time'])) ? $_SESSION['auth']['time'] : null;
    }

    /**
     * Sets the user specified by the parameter as the active user.
     *
     * @param User $user the user to log in
     * @param int $level the level of authentication achieved in this
     * session
     * @param array $modules array of authentication modules used to
     * authenticate the user in this session
     *
     */
    public function login($user, $level, $modules = array(), $form_state = array()) {
        $store = StoreManager::instance();
        if (is_string($user)) $user = $store->loadUser($user);

        $this->f3->set('user', $user);

        if (!isset($_SESSION['auth'])) $_SESSION['auth'] = array();
        $_SESSION['auth']['uid'] = $user['uid'];
        $_SESSION['auth']['level'] = $_SESSION['auth']['next_level'] = $level;
        $_SESSION['auth']['modules'] = $modules;
        $_SESSION['auth']['time'] = time();

        $this->cache->set('user.' . rawurlencode($user['uid']), session_id());

        if ($level > self::AUTH_LEVEL_AUTO) {
            // $user is an object, not an array, and so one cannot modify multi-dimensional
            // arrays
            $uaid = $this->assignUAID();
            $user_auth = (isset($user['auth'])) ? $user['auth'] : array();

            if (!isset($user_auth[$uaid])) $user_auth[$uaid] = array();            
            $user_auth[$uaid]['level'] = $level;
            $user_auth[$uaid]['modules'] = $modules;
            $user_auth[$uaid]['time'] = $_SESSION['auth']['time'];
            $user_auth[$uaid]['remote'] = $this->f3->get('IP');

            $user['auth'] = $user_auth;
            $store->saveUser($user);
        
            $this->logger->log(LogLevel::INFO, 'Login successful: ' . $user['uid'] . '['. gmstrftime('%Y-%m-%dT%H:%M:%SZ', $user['auth_time']) . ']');
        }

        $this->resetUALoginState();

        $this->mgr->invokeAll('login', $user, $level, $modules, $form_state);
    }

    /**
     * Logs out the user by deleting the relevant session information.
     */
    public function logout() {
        $user = $this->getUser();
    
        $this->mgr->invokeAll('logout');

        $this->cache->clear('user.' . rawurlencode($user['uid']));
        $this->f3->clear('user');

        session_unset();
        session_destroy();
        session_write_close();
        $this->f3->set('COOKIE.' . session_name(), '');
        session_regenerate_id(true);

        $this->resetUALoginState();

        $this->logger->log(LogLevel::INFO, 'Logout successful: ' . $user['uid']);
    }


    /**
     * Assigns and returns a unique ID for the user agent (UAID).
     *
     * A UAID uniquely identifies the user agent (e.g. browser) used to
     * make the HTTP request.  The UAID is stored in a long-dated
     * cookie.  Therefore, the UAID may be useful for security purposes.
     *
     * This function will look for a cookie sent by the user agent with
     * the name returned by {@link simpleid_cookie_name()} with a suffix
     * of uaid.  If the cookie does not exist, it will generate a
     * random UAID and return it to the user agent with a Set-Cookie
     * response header.
     *
     * @return string the UAID
     */
    public function assignUAID() {
        $name = 'COOKIE.' . $this->getCookieName('uaid');

        if ($this->f3->exists($name) === true) return $this->f3->get($name);

        $rand = new Random();
        $uaid = $rand->id();

        $this->f3->set($name, $uaid, SIMPLEID_ETERNAL_TOKEN_EXPIRES_IN);

        return $uaid;
    }

    public function getUALoginState() {
        return $this->ua_login_state;
    }

    public function resetUALoginState() {
        $rand = new Random();
        $opaque = new OpaqueIdentifier();

        $this->ua_login_state = $opaque->generate($this->assignUAID() . ':' . $rand->id());

        // We don't use f3->set->COOKIE, as this automatically sets the cookie to be httponly
        // We want this to be script readable.
        setcookie($this->getCookieName('uals'), $this->ua_login_state, 0, '', '', true, false);
    }

    /**
     * Returns a relatively unique cookie name based on a specified suffix.
     *
     * @param string $suffix the cookie name suffix
     * @return string the cookie name
     */
    public function getCookieName($suffix) {
        if (self::$cookie_prefix == NULL) {
            $opaque = new OpaqueIdentifier();
            self::$cookie_prefix = substr($opaque->generate('cookie'), -9) . '_';
        }
        return self::$cookie_prefix . $suffix;
    }
}


?>