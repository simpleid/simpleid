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
    
    // session_name() has to be called before session_set_cookie_params()
    session_name(simpleid_cookie_name('sess'));
    
    // Note the last parameter (httponly) requires PHP 5.2
    session_set_cookie_params(0, get_base_path(), ini_get('session.cookie_domain'), false, true);
    session_start();
    
    if (isset($_SESSION['user']) && (cache_get('user', $_SESSION['user']) == session_id())) {
        $user = user_load($_SESSION['user']);
        
        // If user has just been actively been authenticated in the previous request, then we
        // make it as actively authenticated in this request.
        if (isset($_SESSION['user_auth_active']) && $_SESSION['user_auth_active']) {
            $user['auth_active'] = true;
            unset($_SESSION['user_auth_active']);
        }
    } else {
        if (($q == 'login') || ($q == 'logout')) return;
        user_auto_login();
    }
}

/**
 * Attempts to automatically login using credentials presented by the user agent.
 *
 * The user agent may present various credentials as part of its request.  These
 * may include cookies and SSL client certificates.  This function calls the
 * {@link hook_user_auto_login()} hook of enabled extensions to see if any
 * of these credentials can be used to automatically login a user.
 */
function user_auto_login() {
    global $simpleid_extensions;
    
    $extensions = $simpleid_extensions;
    
    if (!in_array('user_cookieauth', $extensions)) $extensions[] = 'user_cookieauth';
    
    foreach ($extensions as $extension) {
        $test_user = extension_invoke($extension, 'user_auto_login');
        if ($test_user != NULL) {
            _user_login($test_user);
        }
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
    if (isset($user['uid'])) openid_indirect_response(simpleid_url(), '');
    
    // Require HTTPS or return an error
    check_https('error', true);
    
    $destination = (isset($GETPOST['destination'])) ? $GETPOST['destination'] : '';
    $state = (isset($GETPOST['s'])) ? $GETPOST['s'] : '';
    $fixed_uid = (isset($_POST['fixed_uid'])) ? $_POST['name'] : NULL;
    $mode = $_POST['mode'];
    
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

    if (!isset($_POST['mode']) || !in_array($_POST['mode'], array('credentials', 'otp'))) {
        set_message(t('SimpleID detected a potential security attack on your log in.  Please log in again.'));
        user_login_form($destination, $state, $fixed_uid);
        return;
    }

    if (!isset($_POST['nonce'])) {
        if (isset($_POST['destination'])) {
            // User came from a log in form.
            set_message(t('You seem to be attempting to log in from another web page.  You must use this page to log in.'));
        }
        user_login_form($destination, $state, $fixed_uid, $mode);
        return;
    }

    $time = strtotime(substr($_POST['nonce'], 0, 20));
    // Some old versions of PHP does not recognise the T in the ISO 8601 date.  We may need to convert the T to a space
    if (($time == -1) || ($time === FALSE)) $time = strtotime(strtr(substr($_POST['nonce'], 0, 20), 'T', ' '));
    $nonce = cache_get('user-nonce', $_POST['nonce']);
    
    if (!$nonce) {
        log_warn('Login attempt: Nonce ' . $_POST['nonce'] . ' not issued or is being reused.');
        set_message(t('SimpleID detected a potential security attack on your log in.  Please log in again.'));
        user_login_form($destination, $state, $fixed_uid, $mode);
        return;
    } elseif ($time < time() - SIMPLEID_LOGIN_NONCE_EXPIRES_IN) {
        log_notice('Login attempt: Nonce ' . $_POST['nonce'] . ' expired.');
        set_message(t('The log in page has expired.  Please log in again.'));
        user_login_form($destination, $state, $fixed_uid, $mode);
        return;
    } elseif ($nonce['mode'] != $mode) {
        log_warn('Login attempt: Mode saved with nonce ' . $_POST['nonce'] . ' (' . $nonce['mode'] . ') does not match ' . $mode);
        set_message(t('SimpleID detected a potential security attack on your log in.  Please log in again.'));
        user_login_form($destination, $state, $fixed_uid, $mode);
    } else {
        cache_delete('user-nonce', $_POST['nonce']);
    }

    switch ($mode) {
        case 'credentials':
            if (!isset($_POST['name'])) $_POST['name'] = '';
            if (!isset($_POST['pass'])) $_POST['pass'] = '';
            
            if (($_POST['name'] == '') || ($_POST['pass'] == '')) {
                if (isset($_POST['destination'])) {
                    // User came from a log in form.
                    set_message(t('You need to supply the user name and the password in order to log in.'));
                }
                if (isset($_POST['nonce'])) cache_delete('user-nonce', $_POST['nonce']);
                user_login_form($destination, $state, $fixed_uid);
                return;
            }

            if (user_verify_credentials($_POST['name'], $_POST) === false) {
                set_message(t('The user name or password is not correct.'));
                user_login_form($destination, $state, $fixed_uid);
                return;
            }

            $test_user = user_load($_POST['name']);
            if (isset($test_user['otp']) && ($test_user['otp']['type'] != 'recovery')) {
                log_info('One time password required');
                user_login_form($destination, $state, $test_user['uid'], 'otp');
                return;
            }
            break;
        case 'otp':
            if (!isset($_POST['otp']) || ($_POST['otp'] == '')) {
                set_message(t('You need to enter the verification code in order to log in.'));
                if (isset($_POST['nonce'])) cache_delete('user-nonce', $_POST['nonce']);
                user_login_form($destination, $state, $nonce['uid'], 'otp');
                return;
            }

            $test_user = user_load($nonce['uid']);

            if (user_verify_otp($test_user['otp'], $_POST['otp']) === false) {
                set_message(t('The verification code is not correct.'));
                user_login_form($destination, $state, $nonce['uid'], 'otp');
                return;
            }
            user_save($test_user); // Save the drift

            break;
    }
    
    _user_login($test_user, true);
    
    openid_indirect_response(simpleid_url($destination, $query), '');
}

/**
 * Verifies a set of credentials for a specified user.
 *
 * A set of credentials comprises:
 *
 * - A user name
 * - Some kind of verifying information, such as a plaintext password, a hashed
 *   password (e.g. digest) or some other kind of identifying information.
 *
 * The user name is passed to this function using the $uid parameter.  The user
 * name may or may not exist.  If the user name does not exist, this function
 * <strong>must</strong> return false.
 *
 * The credentials are supplied as an array using the $credentials parameter.
 * Typically this array will be a subset of the $_POST superglobal passed to the
 * {@link user_login()} function.  Thus it will generally contain the keys 'pass' and
 * 'digest'.
 *
 * This function calls the {@link hook_user_verify_credentials()} hook to 
 * check whether the credentials supplied matches the credentials
 * for the specified user in the store.
 *
 * @param string $uid the name of the user to verify
 * @param array $credentials the credentials supplied by the browser
 * @return bool whether the credentials supplied matches those for the specified
 * user
 */
function user_verify_credentials($uid, $credentials) {
    global $simpleid_extensions;
    
    $extensions = $simpleid_extensions;
    
    if (!in_array('user_passauth', $extensions)) $extensions[] = 'user_passauth';
    
    foreach ($extensions as $extension) {
        $result = extension_invoke($extension, 'user_verify_credentials', $uid, $credentials);
        if ($result === true) {
            return true;
        }
    }
    
    return false;
}

/**
 * Verifies a one time password (OTP) specified by the user.
 *
 * This function compares an OTP supplied by a user with the OTP
 * calculated based on the current time and the parameters of the
 * algorithm.  The parameters, such as the secret key, are supplied
 * using in $params.  These parameters are typically stored for each
 * user in the user store.
 *
 * To allow for clocks going out of sync, the current time will be
 * by a number (in time steps) specified in $params['drift'].  If
 * the OTP supplied by the user is accepted, $params['drift'] will
 * be also be updated with the latest difference.
 *
 * To allow for network delay, the function will accepts OTPs which
 * is a number of time steps away from the OTP calculated from the
 * adjusted time.  The maximum number of time steps is specified in
 * the $max_drift parameter.
 *
 * @param array &$params the OTP parameters stored
 * @param string $code the OTP supplied by the user
 * @param int $max_drift the maximum drift allowed for network delay, in
 * time steps
 * @return bool whether the OTP supplied matches the OTP generated based on
 * the specified parameters, within the maximum drift
 */
function user_verify_otp(&$params, $code, $max_drift = 1) {
    switch ($params['type']) {
        case 'totp':
            $time = time();

            $test_code = user_totp($params['secret'], $time, $params['period'], $params['drift'], $params['algorithm'], $params['digits']);
            
            if ($test_code == intval($code)) return true;

            for ($i = -$max_drift; $i <= $max_drift; $i++) {
                $test_code = user_totp($params['secret'], $time, $params['period'], $params['drift'] + $i, $params['algorithm'], $params['digits']);
                if ($test_code == intval($code)) {
                    $params['drift'] = $i;
                    return true;
                }
            }
            return false;
            break;
        default:
            return false;
    }
}


/**
 * Sets the user specified by the parameter as the active user.
 *
 * @param array $login_user the user to log in
 * @param bool $auth_active whether the user has been actively authenticated
 * in this session
 *
 */
function _user_login($login_user, $auth_active = false) {
    global $user;

    if ($auth_active) {
        // Set the current authentication time
        $login_user['auth_time'] = time();
        user_save($login_user);
    
        // Set user has been actively authenticated this and the next request only
        $login_user['auth_active'] = true;
        $_SESSION['user_auth_active'] = true;
        log_info('Login successful: ' . $login_user['uid'] . '['. gmstrftime('%Y-%m-%dT%H:%M:%SZ', $login_user['auth_time']) . ']');

    }

    $user = $login_user;
    $_SESSION['user'] = $login_user['uid'];
    cache_set('user', $login_user['uid'], session_id());


    if ($auth_active) {
        if (isset($_POST['autologin']) && ($_POST['autologin'] == 1)) user_cookieauth_create_cookie();
    }
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

    $uid = $user['uid'];
    
    user_cookieauth_invalidate();
    session_destroy();
    
    cache_delete('user', $uid);
    unset($_SESSION['user']);
    $user = NULL;

    log_info('Logout successful: ' . $uid);
}

/**
 * Displays a user login or a login verification form.
 *
 * @param string $destination the SimpleID location to which the user is directed
 * if login is successful
 * @param string $state the current SimpleID state, if required by the location
 * @param string $fixed_uid the user name to be included in the login form; if NULL, the user
 * is asked to supply the user name.  If $mode is otp this cannot be null
 * @param string $mode either credentials (login form) or otp (login verification
 * form)
 */
function user_login_form($destination = '', $state = NULL, $fixed_uid = NULL, $mode = 'credentials') {
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
    cache_set('user-nonce', $nonce, array('mode' => $mode, 'uid' => $fixed_uid));
    
    $base_path = get_base_path();
    $xtpl->assign('javascript', '<script src="' . $base_path . 'html/user-login.js" type="text/javascript"></script>');

    header('X-Frame-Options: DENY');

    switch ($mode) {
        case 'credentials':
            $security_class = (SIMPLEID_ALLOW_AUTOCOMPLETE) ? 'allow-autocomplete ' : '';
            if (is_https()) {
                $security_class .= 'secure';
                $xtpl->assign('security_message', t('Secure login using <strong>HTTPS</strong>.'));
            } elseif (SIMPLEID_ALLOW_PLAINTEXT) {
                $security_class .= 'unsecure';
                $xtpl->assign('security_message', t('<strong>WARNING:</strong>  Your password will be sent to SimpleID as plain text.'));
            }
            $xtpl->assign('security_class', $security_class);
            $xtpl->parse('main.login.login_security');

            extension_invoke_all('user_login_form', $destination, $state);

            $xtpl->assign('name_label', t('User name:'));
            $xtpl->assign('pass_label', t('Password:'));
            $xtpl->assign('autologin_label', t('Remember me on this computer for two weeks.'));

            if ($fixed_uid == NULL) {
                $xtpl->parse('main.login.credentials.input_uid');
            } else {
                $xtpl->assign('uid', htmlspecialchars($fixed_uid, ENT_QUOTES, 'UTF-8'));
                $xtpl->parse('main.login.credentials.fixed_uid');
            }

            $xtpl->parse('main.login.credentials');
            $xtpl->assign('submit_button', t('Log in'));
            $xtpl->assign('title', t('Log In'));
            break;
        case 'otp':
            // Note this is called from user_login(), so $_POST is always filled
            $xtpl->assign('otp_instructions_label', t('To verify your identity, enter the verification code.'));
            $xtpl->assign('otp_recovery_label', t('If you have lost your verification code, you can <a href="!url">recover your account</a>.',
                array('!url' => 'http://simpleid.koinic.net/docs/1/common-problems/#otp')
            ));

            $xtpl->assign('otp_label', t('Verification code:'));
            $xtpl->assign('autologin', (isset($_POST['autologin']) && ($_POST['autologin'] == 1)) ? '1' : '0');
            $xtpl->parse('main.login.otp');
            
            $xtpl->assign('submit_button', t('Verify'));
            $xtpl->assign('title', t('Enter Verification Code'));
        default:
    }


    $xtpl->assign('mode', $mode);
    $xtpl->assign('page_class', 'dialog-page');
    $xtpl->assign('destination', htmlspecialchars($destination, ENT_QUOTES, 'UTF-8'));
    $xtpl->assign('nonce', htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8'));
    
    $xtpl->parse('main.login');
    $xtpl->parse('main.framekiller');
    $xtpl->parse('main');
    $xtpl->out('main');
}

/**
 * Displays the page used to set up login verification using one-time
 * passwords.
 */
function user_otp_page() {
    global $xtpl, $user;

    // Require HTTPS, redirect if necessary
    check_https('redirect', true);
    
    if ($user == NULL) {
        user_login_form('my/profile');
        return;
    }

    if ($_POST['op'] == t('Disable')) {
        if (!isset($_POST['tk']) || !validate_form_token($_POST['tk'], 'dashboard_otp')) {
            set_message(t('SimpleID detected a potential security attack.  Please try again.'));
            page_dashboard();
            return;
        }

        if (isset($user['otp'])) {
            unset($user['otp']);
            user_save($user);
        }
        set_message('Login verification has been disabled.');
        page_dashboard();
        return;
    } elseif ($_POST['op'] == t('Verify')) {
        $params = $_SESSION['otp_setup'];

        if (!isset($_POST['tk']) || !validate_form_token($_POST['tk'], 'otp')) {
            set_message(t('SimpleID detected a potential security attack.  Please try again.'));
            page_dashboard();
            return;
        } elseif (!isset($_POST['otp']) || ($_POST['otp'] == '')) {
            set_message(t('You need to enter the verification code to complete enabling login verification.'));
        } elseif (user_verify_otp($params, $_POST['otp'], 10) === false) {
            set_message(t('The verification code is not correct.'));
        } else {
            unset($_SESSION['otp_setup']);
            $user['otp'] = $params;
            user_save($user);

            set_message('Login verification has been enabled.');
            page_dashboard();
            return;
        }
    } else {
        $params = array(
            'type' => 'totp',
            'secret' => random_bytes(10),
            'algorithm' => 'sha1',
            'digits' => 6,
            'period' => 30,
            'drift' => 0,
        );
        $_SESSION['otp_setup'] = $params;
    }

    $code = strtr(bignum_val(bignum_new($params['secret'], 256), 32), '0123456789abcdefghijklmnopqrstuv', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
    for ($i = 0; $i < strlen($code); $i += 4) {
        $xtpl->assign('secret' . ($i + 1), substr($code, $i, 4));
    }

    $url = 'otpauth://totp/SimpleID?secret=' . $code . '&digits=' . $params['digits'] . '&period=' . $params['period'];
    $xtpl->assign('qr', addslashes($url));

    $xtpl->assign('about_otp', t('Login verification adds an extra layer of protection to your account. When enabled, you will need to enter an additional security code whenever you log into SimpleID.'));
    $xtpl->assign('otp_warning', t('<strong>WARNING:</strong> If you enable login verification and lose your authenticator app, you will need to <a href="!url">edit your identity file manually</a> before you can log in again.',
        array('!url' => 'http://simpleid.koinic.net/docs/1/common-problems/#otp')
    ));

    $xtpl->assign('setup_otp', t('To set up login verification, following these steps.'));
    $xtpl->assign('download_app', t('Download an authenticator app that supports TOTP for your smartphone, such as Google Authenticator.'));
    $xtpl->assign('add_account', t('Add your SimpleID account to authenticator app using this key.  If you are viewing this page on your smartphone you can use <a href="!url">this link</a> or scan the QR code to add your account.',
        array('!url' => $url)
    ));
    $xtpl->assign('verify_code', t('To check that your account has been added properly, enter the verification code from your phone into the box below, and click Verify.'));

    $xtpl->assign('token', get_form_token('otp'));
    $xtpl->assign('otp_label', t('Verification code:'));
    $xtpl->assign('submit_button', t('Verify'));

    $xtpl->assign('page_class', 'dialog-page');
    $xtpl->assign('title', t('Login Verification'));

    $xtpl->parse('main.otp');
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
        header_response_code('400 Bad Request');
        set_message(t('No user specified.'));
    } else {
        $user = user_load($uid);
        
        if ($user == NULL) {
            header_response_code('404 Not Found');
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
 *
 * @param string $ppid the PPID
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
        if (substr(PHP_SAPI, 0,3) === 'cgi') {
            header('Status: 404 Not Found');
        } else {
            header($_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found');
        }
        
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
    $html .= '<p>' . t('To change these, <a href="!url">edit your identity file</a>.', array('!url' => 'http://simpleid.koinic.net/docs/1/identity-files/')) . '</p>';
    
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
 * Verifies a set of credentials using the default user name-password authentication
 * method.
 *
 * @param string $uid the name of the user to verify
 * @param array $credentials the credentials supplied by the browser
 * @return bool whether the credentials supplied matches those for the specified
 * user
 */
function user_passauth_user_verify_credentials($uid, $credentials) {
    $allowed_algorithms = array('md5', 'sha1');
    if (function_exists('hash_algos')) $allowed_algorithms = array_merge($allowed_algorithms, hash_algos());
    if (function_exists('hash_pbkdf2')) $allowed_algorithms[] = 'pbkdf2';
    
    $test_user = user_load($uid);
    
    if ($test_user == NULL) return false;
    
    $hash_function_salt = explode(':', $test_user['pass'], 3);
    
    $hash = $hash_function_salt[0];
    $function = (isset($hash_function_salt[1])) ? $hash_function_salt[1] : 'md5';    
    if (!in_array($function, $allowed_algorithms)) $function = 'md5';
    $salt_suffix = (isset($hash_function_salt[2])) ? ':' . $hash_function_salt[2] : '';

    switch ($function) {
        case 'pbkdf2':
            list ($algo, $iterations, $salt) = explode(':', $hash_function_salt[2]);
            $length = (function_exists('hash')) ? strlen(hash($algo, '')) : 0;
            $test_hash = hash_pbkdf2($algo, $credentials['pass'], $salt, $iterations, $length);
            break;
        case 'md5':
        case 'sha1':
            $test_hash = call_user_func($function, $credentials['pass'] . $salt_suffix);
            break;
        default:
            $test_hash = hash($function, $credentials['pass'] . $salt_suffix);
    }

    return secure_compare($test_hash, $hash);
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
function user_cookieauth_create_cookie($id = NULL, $expires = NULL) {
    global $user;
    
    if ($expires == NULL) {
        log_debug('Automatic login token created for ' . $user['uid']);
    } else {
        log_debug('Automatic login token renewed for ' . $user['uid']);
    }
    
    if ($id == NULL) $id = random_id();
    if ($expires == NULL) $expires = time() + SIMPLEID_USER_AUTOLOGIN_EXPIRES_IN;
    $token = random_secret();
    $uid_hash = get_form_token($user['uid'], FALSE);

    $data = array(
        'uid' => $user['uid'],
        'token' => $token,
        'expires' => $expires,
        'uaid' => get_user_agent_id(),
        'ip' => $_SERVER['REMOTE_ADDR']
    );
    
    cache_set('autologin-'. $uid_hash, $id, $data);
    
    // Note the last parameter (httponly) requires PHP 5.2
    setcookie(simpleid_cookie_name('auth'), 'cookieauth:' . $uid_hash . ':' . $id . ':' . $token, $expires, get_base_path(), '', false, true);
}

/**
 * Verifies a auto login cookie.  If valid, log in the user automatically.
 */
function user_cookieauth_user_auto_login() {
    if (!isset($_COOKIE[simpleid_cookie_name('auth')])) return NULL;
        
    $cookie = $_COOKIE[simpleid_cookie_name('auth')];
    
    list($authtype, $uid_hash, $id, $token) = explode(':', $cookie);
    if ($authtype != 'cookieauth') return NULL;

    log_debug('Automatic login token detected: ' . implode(':', $cookieauth, $uid_hash, $id));
    
    cache_expire(array('autologin-' . $uid_hash => SIMPLEID_USER_AUTOLOGIN_EXPIRES_IN));
    $data = cache_get('autologin-' . $uid_hash, $id);
    
    if (!$data) {  // Cookie doesn't exist
        log_notice('Automatic login: Token does not exist on server');
        return NULL;
    }
    
    if ($data['expires'] < time()) {  // Cookie expired
        log_notice('Automatic login: Token on server expired');
        return NULL;
    }
    
    if ($data['token'] != $token) {
        log_warn('Automatic login: Token on server does not match');
        // Token not the same - panic
        cache_expire(array('autologin-' . $uid_hash => 0));
        user_cookieauth_invalidate();
        return NULL;
    }

    if ($data['uaid'] != get_user_agent_id()) {
        log_warn('Automatic login: User agent ID does not match');
        // Token not the same - panic
        cache_expire(array('autologin-' . $uid_hash => 0));
        user_cookieauth_invalidate();
        return NULL;
    }
    
    // Load the user, tag it as an auto log in
    $test_user = user_load($data['uid']);
    
    if ($test_user != NULL) {
        log_debug('Automatic login token accepted for ' . $data['uid']);
        
        $test_user['autologin'] = TRUE;
    
        // Renew the token
        user_cookieauth_create_cookie($id, $data['expires']);
        
        return $test_user;
    } else {
        log_warn('Automatic login token accepted for ' . $data['uid'] . ', but no such user exists');
        return NULL;
    }
}

/**
 * Removes the auto login cookie from the user agent and the SimpleID
 * cache.
 */
function user_cookieauth_invalidate() {
    if (isset($_COOKIE[simpleid_cookie_name('auth')])) {
        $cookie = $_COOKIE[simpleid_cookie_name('auth')];
        
        list($uid_hash, $id, $token) = explode(':', $cookie);
        
        cache_delete('autologin-' . $uid_hash, $id);
        
        setcookie(simpleid_cookie_name('auth'), "", time() - 3600);
    }
}

/**
 * Calculates a Time-Based One-Time Password (TOTP) based on RFC 6238.
 *
 * This function returns an integer calculated from the TOTP algorithm.
 * The returned integer may need to be zero-padded to return a string
 * with the required number of digits
 *
 * @param string $secret the shared secret as a binary string
 * @param int $time the time to use in the HOTP algorithm.  If NULL, the
 * current time is used
 * @param int $period the time step in seconds
 * @param int $drift the number of time steps to be added to the time to
 * adjust for transmission delay
 * @param string $algorithm the hashing algorithm as supported by
 * the hash_hmac() function
 * @param int $digits the number of digits in the one-time password
 * @return int the one-time password
 * @link http://tools.ietf.org/html/rfc6238
 */
function user_totp($secret, $time = NULL, $period = 30, $drift = 0, $algorithm = 'sha1', $digits = 6) {
    if ($time == NULL) $time = time();
    $counter = floor($time / $period) + $drift;
    $data = pack('NN', 0, $counter);
    return user_hotp($secret, $data, $algorithm, $digits);
}

/**
 * Calculates a HMAC-Based One-Time Password (HOTP) based on RFC 4226.
 *
 * This function returns an integer calculated from the HOTP algorithm.
 * The returned integer may need to be zero-padded to return a string
 * with the required number of digits
 *
 * @param string $secret the shared secret as a binary string
 * @param string $data the counter value as a 64 bit in
 * big endian encoding
 * @param string $algorithm the hashing algorithm as supported by
 * the hash_hmac() function
 * @param int $digits the number of digits in the one-time password
 * @return int the one-time password
 * @link http://tools.ietf.org/html/rfc4226
 */
function user_hotp($secret, $data, $algorithm = 'sha1', $digits = 6) {
    // unpack produces a 1-based array, we use array_merge to convert it to 0-based
    $hmac = array_merge(unpack('C*', hash_hmac(strtolower($algorithm), $data, $secret, true)));
    $offset = $hmac[19] & 0xf;
    $code = ($hmac[$offset + 0] & 0x7F) << 24 |
        ($hmac[$offset + 1] & 0xFF) << 16 |
        ($hmac[$offset + 2] & 0xFF) << 8 |
        ($hmac[$offset + 3] & 0xFF);
    return $code % pow(10, $digits);
}


if (!function_exists('hash_pbkdf2') && function_exists('hash_hmac')) {
    function hash_pbkdf2($algo, $password, $salt, $iterations, $length = 0, $raw_output = false) {
        $result = '';
        $hLen = strlen(hash($algo, '', true));
        if ($length == 0) {
            $length = $hLen;
            if (!$raw_output) $length *= 2;
        }
        $l = ceil($length / $hLen);

        for ($i = 1; $i <= $l; $i++) {
            $U = hash_hmac($algo, $salt . pack('N', $i), $password, true);
            $T = $U;
            for ($j = 1; $j < $iterations; $j++) {
                $T ^= ($U = hash_hmac($algo, $U, $password, true));
            }
            $result .= $T;
        }

        return substr(($raw_output) ? $result : bin2hex($result), 0, $length);
    }
}


?>
