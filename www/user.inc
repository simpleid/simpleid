<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-8
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
 * $Id$
 */

/**
 * User functions.
 *
 * @package simpleid
 * @filesource
 */
 
/**
 * The time the nonce used in the login process will last.
 */
define('SIMPLEID_LOGIN_NONCE_EXPIRES_IN', 3600);

/**
 * The time (in seconds) the auto login cookie will last.  This is currently
 * set as 2 weeks.
 */
define('SIMPLEID_USER_AUTOLOGIN_EXPIRES_IN', 1209600);

/**
 * This variable holds data on the currently logged-in user.  If the user is
 * not logged in, this variable is NULL.
 *
 * @global array $user
 */
$user = NULL;

/**
 * Initialises the user system.  Loads data for the currently logged-in user,
 * if any.
 *
 * @param string $q the SimpleID command, if any
 */
function user_init($q = NULL) {
    global $user;
    global $xtpl;
    
    log_debug('user_init');
    
    $user = NULL;
    
    session_set_cookie_params(0);
    session_name('SESS' . md5(SIMPLEID_BASE_URL));
    session_start();
    
    if (isset($_SESSION['user']) && (cache_get('user', $_SESSION['user']) == session_id())) {
        $user = user_load($_SESSION['user']);
    } elseif (isset($_COOKIE[_user_autologin_cookie()])) {
        if (($q == 'login') || ($q == 'logout')) return;
        user_autologin_verify();
    }
}

/**
 * Loads user data for a specified user name.
 *
 * @param string $uid the name of the user to load
 * @return mixed data for the specified user, or NULL if the user name does not
 * exist
 * @see user_load_from_identity()
 */
function user_load($uid) {
    if (store_user_exists($uid)) {
        $user = store_user_load($uid);
        $user["uid"] = $uid;
        
        if (isset($user["identity"])) {
            $user["local_identity"] = true;
        } else {
            $user["identity"] = simpleid_url('q=user/' . rawurlencode($uid));
            $user["local_identity"] = false;
        }
        
        return $user;
    } else {
        return NULL;
    }
}

/**
 * Loads user data for a specified OpenID Identity URI.
 *
 * @param string $identity the Identity URI of the user to load
 * @return mixed data for the specified user, or NULL if the user name does not
 * exist
 * @see user_load()
 */
function user_load_from_identity($identity) {
    $uid = store_get_uid($identity);
    if ($uid !== NULL) return user_load($uid);
    
    return NULL;
}

/**
 * Stores user data for a specified user name.
 *
 * @param array $user the user to save
 */
function user_save($user) {
    $uid = $user['uid'];
    store_user_save($uid, $user, array('uid', 'identity', 'pass'));
}

/**
 * Attempts to log in a user, using the user name and password specified in the
 * HTTP request.
 */
function user_login() {
    global $user, $GETPOST;
    
    // If the user is already logged in, return
    if (isset($user["uid"])) openid_indirect_response_redirect(simpleid_url(), '');
    
    $destination = $GETPOST['destination'];
    $state = (isset($GETPOST['s'])) ? $GETPOST['s'] : '';
    $query = 'q=' . $destination;
    $query .= ($state) ? '&s=' . rawurlencode($state) : '';
    
    if ($_POST['op'] == 'Cancel') {
        global $version;
        
        $request = unpickle($state);
        $version = openid_get_version($request);
        
        if (isset($request['openid.return_to'])) {
            $return_to = $request['openid.return_to'];
            $response = simpleid_checkid_error(FALSE);
            redirect_form($return_to, $response);
        } else {
            indirect_fatal_error('Login cancelled without a proper OpenID request.');
        }
        return;
    }
    
    // We allow legacy login if the connection is via HTTPS or if SIMPLEID_ALLOW_LEGACY_LOGIN is true
    $allow_legacy_login = (is_https() || SIMPLEID_ALLOW_LEGACY_LOGIN);
    
    if (!isset($_POST['name'])) $_POST['name'] = '';
    if (!isset($_POST['pass'])) $_POST['pass'] = '';
    if (!isset($_POST['digest'])) $_POST['digest'] = '';
    
    if (
        ($_POST['name'] == '')
        || (
            ($allow_legacy_login && ($_POST['pass'] == '') && ($_POST['digest'] == ''))
            || (!$allow_legacy_login && ($_POST['digest'] == ''))
        )
    ) {
        if (isset($_POST['destination'])) {
            // User came from a log in form.
            set_message('You need to supply the user name and the password in order to log in.');
        }
        cache_delete('user-nonce', $_POST['nonce']);
        user_login_form($destination, $state);
        return;
    }
    
    if (!isset($_POST['nonce'])) {
        if (isset($_POST['destination'])) {
            // User came from a log in form.
            set_message('You seem to be attempting to log in from another web page.  You must use this page to log in.');
        }
        user_login_form($destination, $state);
        return;
    }
    
    $time = strtotime(substr($_POST['nonce'], 0, 20));
    
    if (!cache_get('user-nonce', $_POST['nonce'])) {
        log_warn('Login attempt: Nonce ' . $_POST['nonce'] . ' not issued or is being reused.');
        set_message('SimpleID detected a potential security attack on your log in.  Please log in again.');
        user_login_form($destination, $state);
        return;
    } elseif ($time < time() - SIMPLEID_LOGIN_NONCE_EXPIRES_IN) {
        log_notice('Login attempt: Nonce ' . $_POST['nonce'] . ' expired.');
        set_message('The log in page has expired.  Please log in again.');
        user_login_form($destination, $state);
        return;
    } else {
        cache_delete('user-nonce', $_POST['nonce']);
    }
    
    $test_user = user_load($_POST['name']);
    if ($test_user == NULL) {
        set_message('The user name or password is not correct.');
        user_login_form($destination, $state);
        return;
    }
    
    if ($_POST['digest'] && !_user_verify_digest($_POST['digest'], $_POST['nonce'], $test_user)) {
        set_message('The user name or password is not correct.');
        user_login_form($destination, $state);
        return;
    } elseif ($allow_legacy_login && !$_POST['digest'] && (md5($_POST['pass']) != $test_user['pass'])) {
        set_message('The user name or password is not correct.');
        user_login_form($destination, $state);
        return;
    }

    log_info('Login successful: ' . $test_user['uid']);
    _user_login($test_user);
    
    if (isset($_POST['autologin']) && ($_POST['autologin'] == 1)) user_autologin_create();

    openid_indirect_response_redirect(simpleid_url(), $query);
}

/**
 * Sets the user specified by the parameter as the active user.
 *
 * @param array $login_user the user to log in
 *
 */
function _user_login($login_user) {
    global $user;

    $user = $login_user;
    $_SESSION['user'] = $login_user['uid'];
    cache_set('user', $login_user['uid'], session_id());
}

/**
 * Attempts to log out a user and returns to the login form.
 *
 * @param string $destination the destination value to be included in the
 * login form
 */
function user_logout($destination = NULL) {
    global $user, $GETPOST;
    
    $state = (isset($GETPOST['s'])) ? $GETPOST['s'] : '';
    if ($destination == NULL) {
        if (isset($GETPOST['destination'])) {
            $destination = $GETPOST['destination'];
        } else {
            $destination = '';
        }
    }
    
    user_autologin_invalidate();
    
    cache_delete('user', $user['uid']);
    unset($_SESSION['user']);
    $user = NULL;
    
    set_message('You have been logged out.');
    
    user_login_form($destination, $state);
}

/**
 * Displays a user login form.
 *
 * @param string $destination the SimpleID location to which the user is directed
 * if login is successful
 * @param string $state the current SimpleID state, if required by the location
 */
function user_login_form($destination = '', $state = NULL) {    
    global $xtpl;

    if ($state) {
        $xtpl->assign('state', htmlspecialchars($state, ENT_QUOTES, 'UTF-8'));
        $xtpl->parse('main.login.state');
    }
    
    cache_gc(SIMPLEID_LOGIN_NONCE_EXPIRES_IN, 'user-nonce');
    $nonce = openid_nonce();
    cache_set('user-nonce', $nonce, 1);
    
    $xtpl->assign('javascript', '<script src="html/md5.js" type="text/javascript"></script><script src="html/user-login.js" type="text/javascript"></script>');
    
    if (is_https()) {
        $xtpl->assign('security_class', 'secure');
        $xtpl->assign('security_message', 'Secure login using <strong>HTTPS</strong>.');
    } else {
        if (!SIMPLEID_ALLOW_LEGACY_LOGIN) {
            $xtpl->assign('security_class', 'unsecure login-digest');
            $xtpl->assign('security_message', 'Your SimpleID configuration does not allow you to log in unsecurely.  Please enable JavaScript and try again, or see <a href="http://simpleid.sourceforge.net/documentation/using-simpleid/logging-simpleid">the SimpleID documentation</a> for more details.');
            $xtpl->assign('security_disabled', 'disabled="disabled"');
        } else {
            $xtpl->assign('security_class', 'unsecure login-digest');
            $xtpl->assign('security_message', '<strong>WARNING:</strong>  Your password will be sent to SimpleID as plain text.');
        }
    }
    
    extension_invoke_all('user_login_form', $destination, $state);

    $xtpl->assign('title', 'Log In');
    $xtpl->assign('page_class', 'dialog-page');
    $xtpl->assign('destination', htmlspecialchars($destination, ENT_QUOTES, 'UTF-8'));
    $xtpl->assign('nonce', htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8'));
    
    $xtpl->parse('main.login');
    $xtpl->parse('main.framekiller');
    $xtpl->parse('main');
    $xtpl->out('main');
}

/**
 * Returns the user's public page.
 * 
 * @param string $uid the user ID
 */
function user_public_page($uid = NULL) {
    global $xtpl, $user;
    
    $xtpl->assign('title', 'User Page');
    if ($uid == NULL) {
        header('HTTP/1.1 400 Bad Request');
        set_message('No user specified.');
    } else {
        $user = user_load($uid);
        
        if ($user == NULL) {
            header('HTTP/1.1 404 Not Found');
            set_message('User <strong>' . htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') . '</strong> not found.');
        } else {
            header('Vary: Accept');
            
            if (stristr($_SERVER['HTTP_ACCEPT'], 'application/xrds+xml')) {
                user_xrds($uid);
                return;
            } else {
                header('X-XRDS-Location: ' . simpleid_url('q=xrds/' . rawurlencode($uid)));
                
                set_message('This is the user <strong>' . htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') . '</strong>\'s SimpleID page.  It contains hidden information for the use by OpenID consumers.');
                
                $xtpl->assign('title', htmlspecialchars($uid, ENT_QUOTES, 'UTF-8'));
                $xtpl->assign('provider', htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8'));
                $xtpl->assign('xrds', htmlspecialchars(simpleid_url('q=xrds/' . rawurlencode($uid)), ENT_QUOTES, 'UTF-8'));
                if ($user["local_identity"]) {
                    $xtpl->assign('local_id', htmlspecialchars($user["identity"], ENT_QUOTES, 'UTF-8'));
                }
            }
        }
    }
    
    $xtpl->parse('main.provider');
    if ($user["local_identity"]) $xtpl->parse('main.local_id');
    $xtpl->parse('main');
    $xtpl->out('main');
}

/**
 * Returns the user's public XRDS page.
 * 
 * @param string $uid the user ID
 */
function user_xrds($uid) {
    global $xtpl;
    
    $user = user_load($uid);
    
    if ($user != NULL) {
        header('Content-Type: application/xrds+xml');
        header('Content-Disposition: inline; filename=yadis.xml');
    
        if (($user != NULL) && ($user["local_identity"])) {
            $xtpl->assign('local_id', htmlspecialchars($user["identity"], ENT_QUOTES, 'UTF-8'));
            $xtpl->parse('xrds.user_xrds.local_id');
            $xtpl->parse('xrds.user_xrds.local_id2');
        }
    
        $xtpl->assign('simpleid_base_url', htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8'));
        $xtpl->parse('xrds.user_xrds');
        $xtpl->parse('xrds');
        $xtpl->out('xrds');
    } else {
        header('HTTP/1.1 404 Not Found');
        
        set_message('User <strong>' . htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') . '</strong> not found.');
        $xtpl->parse('main');
        $xtpl->out('main');
    }
}

/**
 * Set up the user section in the header, showing the currently logged in user.
 *
 * @param string $state the SimpleID state to retain once the user has logged out,
 * if required.
 */
function user_header($state = NULL) {
    global $user;
    global $xtpl;
    
    if ($user != NULL) {
        $xtpl->assign('uid', htmlspecialchars($user['uid'], ENT_QUOTES, 'UTF-8'));
        $xtpl->assign('identity', htmlspecialchars($user['identity'], ENT_QUOTES, 'UTF-8'));
        if ($state != NULL) {
            $xtpl->assign('state', '&amp;destination=continue&amp;s=' . rawurlencode($state));
            $xtpl->assign('logout', 'Log out and log in as a different user');
        } else {
            $xtpl->assign('logout', 'Log out');
        }
        $xtpl->parse('main.user.logout');
        $xtpl->parse('main.user');
    }
}

/**
 * Verfies a log in name and digest using digest authentication.
 *
 * @param string $digest the digest supplied by the user
 * @param string $nonce the nonce supplied by SimpleID in the initial login
 * form
 * @param mixed $test_user the claimed user, against which to test the user's
 * credentials
 * @return bool true if the verification is successful
 */
function _user_verify_digest($digest, $nonce, $test_user) {
    $test_digest1 = md5($test_user['uid'] . ':' . $test_user['pass']);
    $test_digest = md5($nonce . ':' . $test_digest1);
    return ($digest == $test_digest);
}

/**
 * Creates a auto login cookie.  The login cookie will be based on the
 * current log in user.
 *
 * @param string $id the ID of the series of auto login cookies,  Cookies
 * belonging to the same user and computer have the same ID.  If none is specified,
 * one will be generated
 * @param int $expires the time at which the cookie will expire.  If none is specified
 * the time specified in {@link SIMPLEID_USER_AUTOLOGIN_EXPIRES_IN} will be
 * used
 *
 */
function user_autologin_create($id = NULL, $expires = NULL) {
    global $user;
    
    if ($expires == NULL) {
        log_debug('Automatic login token created for ' . $user['uid']);
    } else {
        log_debug('Automatic login token renewed for ' . $user['uid']);
    }
    
    if ($id == NULL) $id = get_form_token(mt_rand());
    if ($expires == NULL) $expires = time() + SIMPLEID_USER_AUTOLOGIN_EXPIRES_IN;
    $token = get_form_token(mt_rand());
    
    cache_set('autologin-'. $user['uid'], $id, array('token' => $token, 'expires' => $expires, 'ip' => $_SERVER['REMOTE_ADDR']));
    
    setcookie(_user_autologin_cookie(), $user['uid'] . ':' . $id . ':' . $token, $expires);
}

/**
 * Verifies a auto login cookie.  If valid, log in the user automatically.
 */
function user_autologin_verify() {
    $cookie = $_COOKIE[_user_autologin_cookie()];
    
    list($uid, $id, $token) = explode(':', $cookie);
    log_debug('Automatic login token detected for ' . $uid);
    
    cache_gc(SIMPLEID_USER_AUTOLOGIN_EXPIRES_IN, 'autologin-' . $uid);
    $cache = cache_get('autologin-' . $uid, $id);
    
    if (!$cache) {  // Cookie doesn't exist
        log_notice('Automatic login: Token does not exist on server');
        return;
    }
    
    if ($cache['expires'] < time()) {  // Cookie expired
        log_notice('Automatic login: Token on server expired');
        return;
    }
    
    if ($cache['token'] != $token) {
        log_warn('Automatic login: Token on server does not match');
        // Token not the same - panic
        cache_gc(0, 'autologin-' . $uid);
        user_autologin_invalidate();
        return;
    }
    
    // Load the user, tag it as an auto log in
    $user = user_load($uid);
    
    if ($user != NULL) {
        log_debug('Automatic login token accepted for ' . $uid);
        
        $user['autologin'] = TRUE;
        _user_login($user);
    
        // Renew the token
        user_autologin_create($id, $cache['expires']);
    } else {
        log_warn('Automatic login token accepted for ' . $uid . ', but no such user exists');
    }
}

/**
 * Removes the auto login cookie from the user agent and the SimpleID
 * cache.
 */
function user_autologin_invalidate() {
    if (isset($_COOKIE[_user_autologin_cookie()])) {
        $cookie = $_COOKIE[_user_autologin_cookie()];
        
        list($uid, $id, $token) = explode(':', $cookie);
        
        cache_delete('autologin-' . $uid, $id);
        
        setcookie(_user_autologin_cookie(), "", time() - 3600);
    }
}

/**
 * Get the name of the auto login cookie.
 *
 * @return string the name of the persistent login cookie.
 */
function _user_autologin_cookie() {
    return "autologin-" . md5(SIMPLEID_BASE_URL);
}

?>
