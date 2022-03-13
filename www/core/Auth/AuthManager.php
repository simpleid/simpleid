<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2022
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
use \Web\Geo;
use Psr\Log\LogLevel;
use SimpleID\ModuleManager;
use SimpleID\Store\StoreManager;
use SimpleID\Crypt\Random;
use SimpleID\Util\OpaqueIdentifier;
use SimpleID\Util\Events\BaseDataCollectionEvent;
use SimpleID\Util\Forms\FormState;

/**
 * The authentication manager.
 *
 * This simpleton class is responsible for managing the user's
 * authentication session with SimpleID.
 *
 * ## Key concepts
 *
 * The authentication system involves the following key concepts:
 *
 * - **Authentication level.** This is the highest level of user interaction
 *   used to authenticate the user in the current session.  The higher
 *   the authentication level, the more user interaction is required.
 * - **Authentication scheme.** A SimpleID module that implements a way
 *   for a user to authenticate by checking credentials presented against
 *   some data store.
 * - **Authentication mode.** The type of user interaction required for
 *   authentication.
 *
 * ## Process
 *
 * The authentication process works as follows:
 *
 * 1. The PHP session is initialised
 * 2. The session variables are checked for authentication information.
 *    If the information does not exist, the user is not logged in.
 * 3. Invokes each authentication scheme module to see if the user
 *    can be logged in using credentials already stored in the browser
 *    (e.g. cookie, SSL certificate).  Otherwise the user is not
 *    logged in.
 * 4. The user may attempt to log in using the routes presented by
 *    the {@link AuthModule}.
 * 
 *
 */
class AuthManager extends Prefab {
    const AUTH_LEVEL_SESSION = 0;
    const AUTH_LEVEL_TOKEN = 1;
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

    private $auth_info = [];

    private $ua_login_state = null;

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

        if (isset($_SESSION['auth']) && ($this->cache->get(rawurlencode($_SESSION['auth']['uid']) . '.login') == session_id())) {
            $this->auth_info = $_SESSION['auth'];

            $store = StoreManager::instance();
            $user = $store->loadUser($this->auth_info['uid']);
            $this->f3->set('user', $user);
        } elseif ($auto_auth) {
            $event = new AutoAuthEvent();
            \Events::instance()->dispatch($event);

            if ($event->isAuthSuccessful()) {
                $this->login($event);
                return;
            }
        }
    }

    /**
     * Returns whether a user has logged in
     *
     * @return bool true if a user has logged in
     */
    public function isLoggedIn() {
        return (isset($this->auth_info['uid']));
    }

    /**
     * Returns the current logged in user
     *
     * @return \SimpleID\Models\User|null the current logged in user
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
        return (isset($this->auth_info['level'])) ? $this->auth_info['level'] : null;
    }

    /**
     * Returns the time the user was authenticated (including via
     * automatic authentication).
     *
     * @return int the time
     */
    public function getAuthTime() {
        return (isset($this->auth_info['time'])) ? $this->auth_info['time'] : null;
    }

    /**
     * Returns the authentication context class references in relation
     * to the current authentication session.
     *
     * @todo Move to part of the login event
     * @return string the ACR
     */
    public function getACR() {
        $default_acr = $this->f3->get('config.acr');

        if (isset($this->auth_info['modules'])) {
            $event = new BaseDataCollectionEvent('acr');

            foreach ($this->auth_info['modules'] as $module) {
                if (method_exists($module, 'onAcr')) {
                    $module->onAcr($event);
                }
            }
            $module_acr = implode(' ', $event->getResults());
        }

        return (isset($module_acr)) ? $module_acr : $default_acr;
    }

    /**
     * Sets the user specified by the parameter as the active user.
     *
     * @param AuthResultInterface $result the authentication result
     * @param \SimpleID\Util\Forms\FormState $form_state
     */
    public function login(AuthResultInterface $result, $form_state = null) {
        if ($form_state == null) $form_state = new FormState();

        $store = StoreManager::instance();
        $user = $result->getUser();
        $level = $result->getAuthLevel();
        $modules = $result->getAuthModuleNames();

        if (($user == null) && isset($form_state['uid'])) {
            $user = $store->loadUser($form_state['uid']);
        }

        $this->f3->set('user', $user);

        $this->auth_info['uid'] = $user['uid'];
        $this->auth_info['level'] = $level;
        $this->auth_info['modules'] = $modules;
        $this->auth_info['time'] = time();

        if ($level >= self::AUTH_LEVEL_AUTO) {
            $_SESSION['auth'] = $this->auth_info;
            $this->cache->set(rawurlencode($user['uid']) . '.login', session_id());

            $this->assignUALoginState(true);
        }

        if ($level > self::AUTH_LEVEL_AUTO) {
            if (!isset($form_state['auth_skip_activity'])) {
                $activity = [
                    'type' => 'browser',
                    'level' => $level,
                    'modules' => $modules,
                    'time' => $_SESSION['auth']['time'],
                ];
                if ($this->f3->exists('IP')) $activity['remote'] = $this->f3->get('IP');
                if ($this->f3->exists('HEADERS.User-Agent')) $activity['ua'] = $this->f3->get('HEADERS.User-Agent');

                $user->addActivity($this->assignUAID(), $activity);
                $store->saveUser($user);
            }
        
            $this->logger->log(LogLevel::INFO, 'Login successful: ' . $user['uid']);
        }

        $event = new LoginEvent($result, $form_state);
        \Events::instance()->dispatch($event);
    }

    /**
     * Logs out the user by deleting the relevant session information.
     */
    public function logout() {
        $user = $this->getUser();

        $event = new LogoutEvent($user);
        \Events::instance()->dispatch($event);

        $this->cache->clear(rawurlencode($user['uid']) . '.login');
        $this->f3->clear('user');

        session_unset();
        session_destroy();
        session_write_close();
        $this->f3->set('COOKIE.' . session_name(), '');
        session_start();

        $this->assignUALoginState(true);

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
     * the name returned by {@link getCookieName()} with a suffix
     * of uaid.  If the cookie does not exist, it will generate a
     * UAID and return it to the user agent with a Set-Cookie
     * response header.
     *
     * @param bool $reset true to reset the UAID regardless of whether
     * the cookie is present
     * @return string the UAID
     */
    public function assignUAID($reset = false) {
        $name = 'COOKIE.' . $this->getCookieName('uaid');

        if (($this->f3->exists($name) === true) && !$reset) return $this->f3->get($name);

        $rand = new Random();
        $uaid = $rand->id();

        $this->f3->set($name, $uaid, SIMPLEID_ETERNAL_TOKEN_EXPIRES_IN);

        return $uaid;
    }

    /**
     * Assigns and returns a unique login state for the current
     * authenticated session with user agent (UALS).
     *
     * A UALS uniquely identifies the current authenticated session with
     * the user agent (e.g. browser).  It is reset with each successful
     * login and logout.  The cookie associated with a UALS is only
     * valid for the current session.
     *
     * This function will look for a cookie sent by the user agent with
     * the name returned by {@link getCookieName()} with a suffix
     * of uals.  If the cookie does not exist, it will generate a
     * UALS and return it to the user agent with a Set-Cookie
     * response header.
     *
     * @param bool $reset true to reset the UALS
     * @return string the UALS
     */
    public function assignUALoginState($reset = false) {
        $name = $this->getCookieName('uals');
        if (($this->f3->exists('COOKIE.' . $name) === true) && !$reset) {
            $this->ua_login_state = $this->f3->get('COOKIE.' . $name);
        } else {
            $rand = new Random();
            $opaque = new OpaqueIdentifier();

            $this->ua_login_state = $opaque->generate($this->assignUAID() . ':' . $rand->id());

            // We don't use f3->set->COOKIE, as this automatically sets the cookie to be httponly
            // We want this to be script readable.
            setcookie($this->getCookieName('uals'), $this->ua_login_state, 0, $this->f3->get('BASE'), '', true, false);
        }

        return $this->ua_login_state;
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

    public function toString() {
        return print_r($this->auth_info, true);
    }
}


?>