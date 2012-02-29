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
        
        // If user has just been actively been authenticated in the previous request, then we
        // make it as actively authenticated in this request.
        if (isset($_SESSION['user_auth_active']) && $_SESSION['user_auth_active']) {
            $user['auth_active'] = true;
            unset($_SESSION['user_auth_active']);
        }
    } elseif (isset($_COOKIE[_user_autologin_cookie()])) {
        if (($q == 'login') || ($q == 'logout')) return;
        user_autologin_verify();
    } elseif (has_ssl_client_cert()) {
        if ($q == 'logout') return;
        user_cert_login();
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
            $user["identity"] = simpleid_url('user/' . rawurlencode($uid));
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
    if (isset($user["uid"])) openid_indirect_response(simpleid_url(), '');
    
    // Require HTTPS or return an error
    check_https('error', true);
    
    $destination = (isset($GETPOST['destination'])) ? $GETPOST['destination'] : '';
    $state = (isset($GETPOST['s'])) ? $GETPOST['s'] : '';
    $query = ($state) ? 's=' . rawurlencode($state) : '';
    
    if (isset($_POST['op']) && $_POST['op'] == t('Cancel')) {
        global $version;
        
        $request = unpickle($state);
        $version = openid_get_version($request);
        
        if (isset($request['openid.return_to'])) {
            $return_to = $request['openid.return_to'];
            $response = simpleid_checkid_error(FALSE);
            simpleid_assertion_response($response, $return_to);
        } else {
            indirect_fatal_error(t('Login cancelled without a proper OpenID request.'));
        }
        return;
    }
    
    if (!isset($_POST['name'])) $_POST['name'] = '';
    if (!isset($_POST['pass'])) $_POST['pass'] = '';
    
    if (($_POST['name'] == '') || ($_POST['pass'] == '')) {
        if (isset($_POST['destination'])) {
            // User came from a log in form.
            set_message(t('You need to supply the user name and the password in order to log in.'));
        }
        if (isset($_POST['nonce'])) cache_delete('user-nonce', $_POST['nonce']);
        user_login_form($destination, $state);
        return;
    }
    
    if (!isset($_POST['nonce'])) {
        if (isset($_POST['destination'])) {
            // User came from a log in form.
            set_message(t('You seem to be attempting to log in from another web page.  You must use this page to log in.'));
        }
        user_login_form($destination, $state);
        return;
    }
    
    $time = strtotime(substr($_POST['nonce'], 0, 20));
    // Some old versions of PHP does not recognise the T in the ISO 8601 date.  We may need to convert the T to a space
    if (($time == -1) || ($time === FALSE)) $time = strtotime(strtr(substr($_POST['nonce'], 0, 20), 'T', ' '));
    
    if (!cache_get('user-nonce', $_POST['nonce'])) {
        log_warn('Login attempt: Nonce ' . $_POST['nonce'] . ' not issued or is being reused.');
        set_message(t('SimpleID detected a potential security attack on your log in.  Please log in again.'));
        user_login_form($destination, $state);
        return;
    } elseif ($time < time() - SIMPLEID_LOGIN_NONCE_EXPIRES_IN) {
        log_notice('Login attempt: Nonce ' . $_POST['nonce'] . ' expired.');
        set_message(t('The log in page has expired.  Please log in again.'));
        user_login_form($destination, $state);
        return;
    } else {
        cache_delete('user-nonce', $_POST['nonce']);
    }
    
    if (store_user_verify_credentials($_POST['name'], $_POST) === false) {
        set_message(t('The user name or password is not correct.'));
        user_login_form($destination, $state);
        return;
    }
    
    // Set the current authentication time
    $test_user = user_load($_POST['name']);
    $test_user['auth_time'] = time();
    user_save($test_user);
    
    // Set user has been actively authenticated this and the next request only
    $test_user['auth_active'] = true;
    $_SESSION['user_auth_active'] = true;
    
    _user_login($test_user);
    log_info('Login successful: ' . $test_user['uid'] . '['. gmstrftime('%Y-%m-%dT%H:%M:%SZ', $test_user['auth_time']) . ']');
    
    
    if (isset($_POST['autologin']) && ($_POST['autologin'] == 1)) user_autologin_create();

    openid_indirect_response(simpleid_url($destination, $query), '');
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
    
    // Require HTTPS, redirect if necessary
    check_https('redirect', true);
    
    $state = (isset($GETPOST['s'])) ? $GETPOST['s'] : '';
    if ($destination == NULL) {
        if (isset($GETPOST['destination'])) {
            $destination = $GETPOST['destination'];
        } else {
            $destination = '';
        }
    }
    
    _user_logout();
    
    set_message(t('You have been logged out.'));
    
    user_login_form($destination, $state);
}

/**
 * Logs out the user by deleting the relevant session information.
 */
function _user_logout() {
    global $user;
    
    user_autologin_invalidate();
    session_destroy();
    
    cache_delete('user', $user['uid']);
    unset($_SESSION['user']);
    $user = NULL;
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
    
    // Require HTTPS, redirect if necessary
    check_https('redirect', true);

    if ($state) {
        $xtpl->assign('state', htmlspecialchars($state, ENT_QUOTES, 'UTF-8'));
        $xtpl->assign('cancel_button', t('Cancel'));
        $xtpl->parse('main.login.state');
    }
    
    cache_expire(array('user-nonce' => SIMPLEID_LOGIN_NONCE_EXPIRES_IN));
    $nonce = openid_nonce();
    cache_set('user-nonce', $nonce, 1);
    
    $base_path = get_base_path();
    
    $xtpl->assign('javascript', '<script src="' . $base_path . 'html/user-login.js" type="text/javascript"></script>');
    
    $security_class = (SIMPLEID_ALLOW_AUTOCOMPLETE) ? 'allow-autocomplete ' : '';
    
    if (is_https()) {
        $security_class .= 'secure';
        $xtpl->assign('security_message', t('Secure login using <strong>HTTPS</strong>.'));
    } elseif (SIMPLEID_ALLOW_PLAINTEXT) {
        $security_class .= 'unsecure';
        $xtpl->assign('security_message', t('<strong>WARNING:</strong>  Your password will be sent to SimpleID as plain text.'));
    }
    $xtpl->assign('security_class', $security_class);
    
    extension_invoke_all('user_login_form', $destination, $state);
    
    header('X-Frame-Options: DENY');

    $xtpl->assign('name_label', t('User name:'));
    $xtpl->assign('pass_label', t('Password'));
    $xtpl->assign('autologin_label', t('Remember me on this computer for two weeks.'));
    $xtpl->assign('login_button', t('Log in'));
    
    $xtpl->assign('title', t('Log In'));
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
    
    $xtpl->assign('title', t('User Page'));
    if ($uid == NULL) {
        header('HTTP/1.1 400 Bad Request');
        set_message(t('No user specified.'));
    } else {
        $user = user_load($uid);
        
        if ($user == NULL) {
            header('HTTP/1.1 404 Not Found');
            set_message(t('User %uid not found.', array('%uid' => $uid)));
        } else {
            header('Vary: Accept');
            
            $content_type = negotiate_content_type(array('text/html', 'application/xml', 'application/xhtml+xml', 'application/xrds+xml'));
            
            if ($content_type == 'application/xrds+xml') {
                user_xrds($uid);
                return;
            } else {
                header('X-XRDS-Location: ' . simpleid_url('xrds/' . rawurlencode($uid)));
                
                set_message(t('This is the user %uid\'s SimpleID page.  It contains hidden information for the use by OpenID consumers.', array('%uid' => $uid)));
                
                $xtpl->assign('title', htmlspecialchars($uid, ENT_QUOTES, 'UTF-8'));
                $xtpl->assign('provider', htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8'));
                $xtpl->assign('xrds', htmlspecialchars(simpleid_url('xrds/' . rawurlencode($uid)), ENT_QUOTES, 'UTF-8'));
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
 * Returns the public page for a private personal ID.
 */
function user_ppid_page($ppid = NULL) {
    global $xtpl;
    
    header('Vary: Accept');
            
    $content_type = negotiate_content_type(array('text/html', 'application/xml', 'application/xhtml+xml', 'application/xrds+xml'));
            
    if (($content_type == 'application/xrds+xml') || ($_GET['format'] == 'xrds')) {
        header('Content-Type: application/xrds+xml');
        header('Content-Disposition: inline; filename=yadis.xml');
    
        $xtpl->assign('simpleid_base_url', htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8'));
        $xtpl->parse('xrds.user_xrds');
        $xtpl->parse('xrds');
        $xtpl->out('xrds');
        return;
    } else {
        header('X-XRDS-Location: ' . simpleid_url('ppid/' . rawurlencode($ppid), 'format=xrds'));
                
        $xtpl->assign('title', t('Private Personal Identifier'));
                
        set_message(t('This is a private personal identifier.'));
        
        $xtpl->parse('main');
        $xtpl->out('main');
    }   
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
 * Returns a block containing OpenID Connect user information.
 *
 * @return array the OpenID Connect user information block
 */
function _user_page_profile() {
    global $user;
    
    $html = '<p>' . t('SimpleID may, with your consent, send the following information to sites which supports OpenID Connect.') . '</p>';    
    $html .= '<p>' . t('To change these, <a href="!url">edit your identity file</a>.', array('!url' => 'http://simpleid.sourceforge.net/documentation/getting-started/setting-identity/identity-files')) . '</p>';
    
    $html .= "<table><tr><th>" . t('Member') . "</th><th>" . t('Value') . "</th></tr>";
    
    if (isset($user['user_info'])) {
        foreach ($user['user_info'] as $member => $value) {
            if (is_array($value)) {
                foreach ($value as $submember => $subvalue) {
                    $html .= "<tr><td>" . htmlspecialchars($member, ENT_QUOTES, 'UTF-8') . " (" .htmlspecialchars($submember, ENT_QUOTES, 'UTF-8') . ")</td><td>" . htmlspecialchars($subvalue, ENT_QUOTES, 'UTF-8') . "</td></tr>";
                }
            } else {
                $html .= "<tr><td>" . htmlspecialchars($member, ENT_QUOTES, 'UTF-8') . "</td><td>" . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . "</td></tr>";
            }
        }
    }
    
    $html .= "</table>";
    
    return array(array(
        'id' => 'userinfo',
        'title' => t('OpenID Connect'),
        'content' => $html
    ));
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
            $xtpl->assign('url', htmlspecialchars(simpleid_url('logout', 'destination=continue&s=' . rawurlencode($state), true)));
            $xtpl->assign('logout', t('Log out and log in as a different user'));
        } else {
            $xtpl->assign('url', htmlspecialchars(simpleid_url('logout', '', true)));
            $xtpl->assign('logout', t('Log out'));
        }
        $xtpl->parse('main.user.logout');
        $xtpl->parse('main.user');
    }
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
    
    cache_set('autologin-'. md5($user['uid']), $id, array('token' => $token, 'expires' => $expires, 'ip' => $_SERVER['REMOTE_ADDR']));
    
    setcookie(_user_autologin_cookie(), $user['uid'] . ':' . $id . ':' . $token, $expires);
}

/**
 * Verifies a auto login cookie.  If valid, log in the user automatically.
 */
function user_autologin_verify() {
    $cookie = $_COOKIE[_user_autologin_cookie()];
    
    list($uid, $id, $token) = explode(':', $cookie);
    log_debug('Automatic login token detected for ' . $uid);
    
    cache_expire(array('autologin-' . md5($uid) => SIMPLEID_USER_AUTOLOGIN_EXPIRES_IN));
    $cache = cache_get('autologin-' . md5($uid), $id);
    
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
        cache_expire(array('autologin-' . md5($uid) => 0));
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
        
        cache_delete('autologin-' . md5($uid), $id);
        
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

/**
 * Attempt to login using a SSL client certificate.
 *
 * Note that the web server must be set up to request a SSL client certificate
 * and pass the certificate's details to PHP.
 */
function user_cert_login() {
    $cert = trim($_SERVER['SSL_CLIENT_M_SERIAL']) . ';' . trim($_SERVER['SSL_CLIENT_I_DN']);
    log_debug('Client SSL certificate: ' . $cert);
    
    $uid = store_get_uid_from_cert($cert);
    if ($uid != NULL) {
        log_debug('Client SSL certificate accepted for ' . $uid);
        $user = user_load($uid);
        _user_login($user);
    } else {
        log_warn('Client SSL certificate presented, but no user with that certificate exists.');
    }
}
?>
