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
 * The time the persistent login cookie will last.
 */
define('SIMPLEID_USER_PERSISTENCE_EXPIRES_IN', 50400);

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
    
    $user = NULL;
    
    session_set_cookie_params(0);
    session_start();
    
    if (isset($_SESSION['user']) && (cache_get('user', $_SESSION['user']) == session_id())) {
        $user = user_load($_SESSION['user']);
    } elseif (isset($_COOKIE[_user_persistence_cookie()])) {
        if (($q == 'login') || ($q == 'logout')) return;
        user_persistence_verify();
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
    $identity_file = SIMPLEID_IDENTITIES_DIR . "/$uid.identity";    
    
    if (file_exists($identity_file)) {
        $user = parse_ini_file($identity_file, TRUE);
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
    $uid = cache_get('identity', $identity);
    $r = NULL;
    
    if ($uid !== NULL) {
        return user_load($uid);
    } else {
        $dir = opendir(SIMPLEID_IDENTITIES_DIR);
        
        while (($file = readdir($dir)) !== false) {
            $filename = SIMPLEID_IDENTITIES_DIR . '/' . $file;                        
            
            if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.identity$/', $file, $matches))) continue;            
            
            $uid = $matches[1];
            $test_user = user_load($uid);
            
            cache_set('identity', $test_user['identity'], $uid);
        
            if ($test_user['identity'] == $identity) {
                $r = $test_user;
            }
        }
        
        closedir($dir);
    }
    
    return $r;
}

/**
 * Attempts to log in a user, using the user name and password specified in the
 * HTTP request.
 */
function user_login() {
    global $user;
    
    // If the user is already logged in, return
    if (isset($user["uid"])) openid_indirect_response_redirect(simpleid_url(), 'q=frontpage');
    
    $destination = $_REQUEST['destination'];
    $state = $_REQUEST['s'];
    $query = 'q=' . $destination;
    $query .= ($state) ? '&s=' . rawurlencode($state) : '';
    
    if (!$_POST['name'] || ((SIMPLEID_ALLOW_LEGACY_LOGIN && (!$_POST['pass']) && (!$_POST['digest'])) || (!SIMPLEID_ALLOW_LEGACY_LOGIN && (!$_POST['digest'])))) {
        if (isset($_POST['destination'])) {
            // User came from a log in form.
            set_message('You need to supply the user name and the password in order to log in.');
        }
        cache_delete('user-nonce', $_POST['nonce']);
        user_login_form($destination, $state);
        return;
    }
    
    if (!$_POST['nonce']) {
        if (isset($_POST['destination'])) {
            // User came from a log in form.
            set_message('You seem to be attempting to log in from another web page.  You must use this page to log in.');
        }
        user_login_form($destination, $state);
        return;
    }
    
    $time = strtotime(substr($_POST['nonce'], 0, 20));
    
    if (!cache_get('user-nonce', $_POST['nonce'])) {
        set_message('SimpleID detected a potential security attack on your log in.  Please log in again.');
        user_login_form($destination, $state);
        return;
    } elseif ($time < time() - SIMPLEID_LOGIN_NONCE_EXPIRES_IN) {
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
    } elseif (SIMPLEID_ALLOW_LEGACY_LOGIN && (md5($_POST['pass']) != $test_user['pass'])) {
        set_message('The user name or password is not correct.');
        user_login_form($destination, $state);
        return;
    }

    _user_login($test_user);
    
    if ($_POST['persistent'] == 1) user_persistence_create();

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
    $_SESSION['user'] = $_POST['name'];
    cache_set('user', $_POST['name'], session_id());
}

/**
 * Attempts to log out a user and returns to the login form.
 *
 * @param string $destination the destination value to be included in the
 * login form
 */
function user_logout($destination = NULL) {
    global $user;
    
    $state = $_REQUEST['s'];
    if ($destination == NULL) {
        if ($_REQUEST['destination']) {
            $destination = $_REQUEST['destination'];
        } else {
            $destination = '';
        }
    }
    
    user_persistence_invalidate();
    
    cache_delete('user', $user['uid']);
    unset($_SESSION['user']);
    $user = NULL;
    
    set_message('You have been logged out.');
    
    user_login_form($destination, $state);
}

/**
 * Provides a user login form.
 *
 * @param string $destination the SimpleID location to which the user is directed
 * if login is successful
 * @param string $state the current SimpleID state, if required by the location
 */
function user_login_form($destination = '', $state = NULL) {    
    global $xtpl;

    cache_gc(SIMPLEID_LOGIN_NONCE_EXPIRES_IN, 'user-nonce');
    $nonce = openid_nonce();
    cache_set('user-nonce', $nonce, 1);
    
    $xtpl->assign('javascript', '<script src="html/md5.js" type="text/javascript"></script><script src="html/user-login.js" type="text/javascript"></script>');
    
    if (isset($_SERVER['HTTPS'])) {
        $xtpl->assign('security_class', 'secure');
        $xtpl->assign('security_message', 'Secure login using <strong>HTTPS</strong>.');
    } else {
        $xtpl->assign('security_class', 'unsecure');
        
        if (!SIMPLEID_ALLOW_LEGACY_LOGIN) {
            $xtpl->assign('security_message', 'Your SimpleID configuration does not allow you to log in unsecurely.  Please enable JavaScript and try again, or see <a href="http://simpleid.sourceforge.net/manual/login-security.html">the SimpleID manual</a> for more details.');
            $xtpl->assign('security_disabled', 'disabled="disabled"');
        } else {
            $xtpl->assign('security_message', '<strong>WARNING:</strong>  Your password will be sent to SimpleID as plain text.');
        }
    }
    
    $xtpl->assign('title', 'Log In');
    $xtpl->assign('destination', htmlspecialchars($destination, ENT_QUOTES, 'UTF-8'));
    $xtpl->assign('nonce', htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8'));
    if ($state) $xtpl->assign('state', $state);
    
    $xtpl->parse('main.login');
    $xtpl->parse('main');
    $xtpl->out('main');
}

/**
 * Returns the user's home page.
 */
function user_page() {
    global $user;
    global $xtpl;
    
    if ($user == NULL) {
        user_login_form('');
        return;
    }
    
    user_block();
    
    $rps = simpleid_rp_load_all($user['uid']);
    
    if ($rps) {
        foreach ($rps as $realm => $rp) {
            $xtpl->assign('realm', htmlspecialchars($rp['realm'], ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('last_time', htmlspecialchars(strftime(SIMPLEID_DATE_TIME_FORMAT, $rp['last_time']), ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('auto_release', ($rp['auto_release']) ? 'checked="checked"' : '');
            $xtpl->parse('main.frontpage.realm');
        }
    }
    
    $xtpl->assign('token', get_form_token('autorelease'));
    
    $extensions = extension_invoke_all('user_page');
    $xtpl->assign('extensions', implode($extensions));
    
    $xtpl->parse('main.frontpage');
    
    $xtpl->assign('title', 'Home Page');
    $xtpl->parse('main');
    $xtpl->out('main');
}

/**
 * Returns the user's public page.
 * 
 * @param string $uid the user ID
 */
function user_public_page($uid = NULL) {
    global $xtpl;
    
    $xtpl->assign('title', 'User Page');
    if ($uid == NULL) {
        header('Status: 500');
        set_message('No user specified.');
    } else {
        $user = user_load($uid);
        
        if ($user == NULL) {
            header('Status: 500');
            set_message('User <strong>' . htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') . '</strong> not found.');
        } else {
            header('X-XRDS-Location', simpleid_url('q=xrds/' . rawurlencode($uid)));
            
            set_message('This is the user <strong>' . htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') . '</strong>\'s SimpleID page.  It contains hidden information for the use by OpenID consumers.');
            
            $xtpl->assign('title', htmlspecialchars($uid, ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('provider', htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('xrds', htmlspecialchars(simpleid_url('q=xrds/' . rawurlencode($uid)), ENT_QUOTES, 'UTF-8'));
            if ($user["local_identity"]) {
                $xtpl->assign('local_id', htmlspecialchars($user["identity"], ENT_QUOTES, 'UTF-8'));
            }
        }
    }
    
    $xtpl->parse('main.provider');
    if ($user["local_identity"]) $xtpl->parse('main.local_id');
    $xtpl->parse('main');
    $xtpl->out('main');
}

/**
 * Returns the user's public XDRS page.
 * 
 * @param string $uid the user ID
 */
function user_xrds($uid = NULL) {
    global $xtpl;
    
    header('Content-Type: application/xrds+xml');
    header('Content-Disposition: inline; filename=yadis.xml');
    
    if ($uid != NULL) {
        $user = user_load($uid);
        if (($user != NULL) && ($user["local_identity"])) {
            $xtpl->assign('local_id', htmlspecialchars($user["identity"], ENT_QUOTES, 'UTF-8'));
            $xtpl->parse('xrds.local_id');
            $xtpl->parse('xrds.local_id2');
        }
    }
    
    $xtpl->assign('simpleid_base_url', htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8'));
    $xtpl->parse('xrds');
    $xtpl->out('xrds');
}

/**
 * Set up the user block, showing the currently logged in user.
 *
 * @param bool $allow_logout whether to include a logout link
 */
function user_block($allow_logout = TRUE) {
    global $user;
    global $xtpl;
    
    if ($user != NULL) {
        $xtpl->assign('uid', htmlspecialchars($user['uid'], ENT_QUOTES, 'UTF-8'));
        $xtpl->assign('identity', htmlspecialchars($user['identity'], ENT_QUOTES, 'UTF-8'));
        if ($allow_logout) $xtpl->assign('logout', '<a href="?q=logout">Logout</a>');
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
 * Creates a persistent login cookie.  The login cookie will be based on the
 * current log in user.
 *
 * @param string $id the ID of the series of persistent login cookies,  Cookies
 * belonging to the same user and computer have the same ID.  If none is specified,
 * one will be generated
 * @param int $expires the time at which the cookie will expire.  If none is specified
 * the time specified in {@link SIMPLEID_USER_PERSISTENCE_EXPIRES_IN} will be
 * used
 *
 */
function user_persistence_create($id = NULL, $expires = NULL) {
    global $user;
    
    if ($id == NULL) $id = get_form_token(mt_rand());
    if ($expires == NULL) $expires = time() + SIMPLEID_USER_PERSISTENCE_EXPIRES_IN;
    $token = get_form_token(mt_rand());
    
    cache_set('persistence-'. $user['uid'], $id, array('token' => $token, 'expires' => $expires, 'ip' => $_SERVER['REMOTE_ADDR']));
    
    setcookie(_user_persistence_cookie(), $user['uid'] . ':' . $id . ':' . $token, $expires);
}

/**
 * Verifies a persistent login cookie.  If valid, log in the user automatically.
 */
function user_persistence_verify() {
    $cookie = $_COOKIE[_user_persistence_cookie()];
    
    list($uid, $id, $token) = explode(':', $cookie);
    
    cache_gc(SIMPLEID_USER_PERSISTENCE_EXPIRES_IN, 'persistence-' . $uid);
    $cache = cache_get('persistence-' . $uid, $id);
    
    if (!$cache) return;  // Cookie doesn't exist
    
    if ($cache['expires'] < time()) return;  // Cookie expired
    
    if ($cache['token'] != $token) {
        // Token not the same - panic
        cache_gc(0, 'persistence-' . $uid);
        user_persistence_invalidate();
        return;
    }
    
    // Load the user, tag it as a persistent log in
    $user = user_load($uid);
    $user['persistent'] = TRUE;
    _user_login($user);
    
    // Renew the token
    user_persistence_create($id, $cache['expires']);
}

/**
 * Removes the persistent login cookie from the user agent and the SimpleID
 * cache.
 */
function user_persistence_invalidate() {
    if (isset($_COOKIE[_user_persistence_cookie()])) {
        $cookie = $_COOKIE[_user_persistence_cookie()];
        
        list($uid, $id, $token) = explode(':', $cookie);
        
        cache_delete('persistence-' . $uid, $id);
        
        setcookie(_user_persistence_cookie(), "", time() - 3600);
    }
}

/**
 * Get the name of the persistent login cookie.
 *
 * @return string the name of the persistent login cookie.
 */
function _user_persistence_cookie() {
    return "persistence-" . md5(SIMPLEID_BASE_URL);
}

?>
