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
 
define('SIMPLEID_LOGIN_NONCE_EXPIRES_IN', 3600);

function user_init() {
    global $user;
    global $xtpl;
    
    $user = NULL;
    
    session_start();    
    
    if (isset($_SESSION['user']) && (cache_get('user', $_SESSION['user']) == session_id())) {
        $user = user_load($_SESSION['user']);
    }
}

function user_load($uid) {
    $identity_file = SIMPLEID_IDENTITIES_DIR . "/$uid.identity";    
    
    if (file_exists($identity_file)) {
        $user = parse_ini_file($identity_file, TRUE);
        $user["uid"] = $uid;
        
        if (isset($user["identity"])) {
            $user["local_identity"] = true;
        } else {
            $user["identity"] = SIMPLEID_BASE_URL . '/index.php?q=user/' . $uid;
            $user["local_identity"] = false;
        }
        
        return $user;
    } else {
        return NULL;
    }
}

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

function user_login() {
    global $user;
    
    // If the user is already logged in, return
    if (isset($user["uid"])) openid_indirect_response_redirect(SIMPLEID_BASE_URL, 'q=frontpage');
    
    $destination = $_REQUEST['destination'];
    $state = $_REQUEST['s'];
    $query = 'q=' . $destination;
    $query .= ($state) ? '&s=' . urlencode($state) : '';
    
    if (!$_POST['name'] || !$_POST['pass']) {
        if (isset($_POST['destination'])) {
            // User came from a log in form.
            set_message('You need to supply the user name and the password in order to log in.');
        }
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
        set_message('The user you have supplied does not exist.');
        user_login_form($destination, $state);
        return;
    }
    
    if (md5($_POST['pass']) != $test_user['pass']) {
        set_message('The user name or password is not correct.');
        user_login_form($destination, $state);
        return;
    }
    
    $user = $test_user;
    $_SESSION['user'] = $_POST['name'];
    cache_set('user', $_POST['name'], session_id());

    openid_indirect_response_redirect(SIMPLEID_BASE_URL, $query);
}

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
    
    cache_delete('user', $user['uid']);
    unset($_SESSION['user']);
    $user = NULL;
    
    set_message('You have been logged out.');
    
    user_login_form($destination, $state);
}


function user_login_form($destination = '', $state = NULL) {    
    global $xtpl;

    cache_gc(SIMPLEID_LOGIN_NONCE_EXPIRES_IN, 'user-nonce');
    $nonce = openid_nonce();
    cache_set('user-nonce', $nonce, 1);
    
    $xtpl->assign('title', 'Log In');
    $xtpl->assign('destination', htmlspecialchars($destination));
    $xtpl->assign('captcha_hash', md5(SIMPLEID_BASE_URL . ($a + $b)));
    $xtpl->assign('nonce', htmlspecialchars($nonce));
    if ($state) $xtpl->assign('state', $state);
    
    $xtpl->parse('main.login');
    $xtpl->parse('main');
    $xtpl->out('main');
}

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
            $xtpl->assign('realm', htmlspecialchars($rp['realm']));
            $xtpl->assign('last_time', htmlspecialchars(strftime(SIMPLEID_DATE_TIME_FORMAT, $rp['last_time'])));
            $xtpl->assign('auto_release', ($rp['auto_release']) ? 'checked="checked"' : '');
            $xtpl->parse('main.frontpage.realm');
        }
    }
    
    $extensions = extension_invoke_all('user_page');
    $xtpl->assign('extensions', implode($extensions));
    
    $xtpl->parse('main.frontpage');
    
    $xtpl->assign('title', 'Home Page');
    $xtpl->parse('main');
    $xtpl->out('main');
}

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
            set_message('User <strong>' . htmlspecialchars($uid) . '</strong> not found.');
        } else {
            header('X-XRDS-Location', SIMPLEID_BASE_URL . '/index.php?q=xrds/' . $uid);
            
            set_message('This is the user <strong>' . htmlspecialchars($uid) . '</strong>\'s SimpleID page.  It contains hidden information for the use by OpenID consumers.');
            
            $xtpl->assign('title', htmlspecialchars($uid));
            $xtpl->assign('provider', htmlspecialchars(SIMPLEID_BASE_URL));
            $xtpl->assign('xrds', htmlspecialchars(SIMPLEID_BASE_URL . '/index.php?q=xrds/' . $uid));
            if ($user["local_identity"]) {
                $xtpl->assign('local_id', htmlspecialchars($user["identity"]));
            }
        }
    }
    
    $xtpl->parse('main.provider');
    if ($user["local_identity"]) $xtpl->parse('main.local_id');
    $xtpl->parse('main');
    $xtpl->out('main');
}

function user_xrds($uid = NULL) {
    global $xtpl;
    
    header('Content-Type: application/xrds+xml');
    header('Content-Disposition: inline; filename=yadis.xml');
    
    if ($uid != NULL) {
        $user = user_load($uid);
        if (($user != NULL) && ($user["local_identity"])) {
            $xtpl->assign('local_id', htmlspecialchars($user["identity"]));
            $xtpl->parse('xrds.local_id');
            $xtpl->parse('xrds.local_id2');
        }
    }
    
    $xtpl->assign('simpleid_base_url', htmlspecialchars(SIMPLEID_BASE_URL));
    $xtpl->parse('xrds');
    $xtpl->out('xrds');
}

function user_block($allow_logout = TRUE) {
    global $user;
    global $xtpl;
    
    if ($user != NULL) {
        $xtpl->assign('uid', htmlspecialchars($user['uid']));
        $xtpl->assign('identity', htmlspecialchars($user['identity']));
        if ($allow_logout) $xtpl->assign('logout', '<a href="?q=logout">Logout</a>');
        $xtpl->parse('main.user');
    }
}

?>
