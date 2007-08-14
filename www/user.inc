<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007
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
    if (isset($user["uid"])) redirect_http(SIMPLEID_BASE_URL, 'q=frontpage');
    
    $destination = $_POST['destination'];
    
    if (!$_POST['name'] || !$_POST['pass'] || !$_POST['captcha']) {
        set_message('You need to supply the user name, the password and the answer to the maths question in order to log in.');
        user_login_form($destination);
        return;
    }
    
    if (md5(SIMPLEID_BASE_URL . trim($_POST['captcha'])) != $_POST['captcha_hash']) {
        set_message('Your answer to the maths question is not correct.');
        user_login_form($destination);
        return;
    }
    
    $test_user = user_load($_POST['name']);
    if ($test_user == NULL) {
        set_message('The user you have supplied does not exist.');
        user_login_form($destination);
        return;
    }
    
    if (md5($_POST['pass']) != $test_user['pass']) {
        set_message('The user name or password is not correct.');
        user_login_form($destination);
        return;
    }
    
    $user = $test_user;
    $_SESSION['user'] = $_POST['name'];
    cache_set('user', $_POST['name'], session_id());
    //session_regenerate_id();

    redirect_http(SIMPLEID_BASE_URL, 'q=' . $destination);
}

function user_logout($destination = 'frontpage') {
    global $user;
    
    cache_delete('user', $user['uid']);
    unset($_SESSION['user']);
    
    $user = NULL;
    user_login_form($destination);
}


function user_login_form($destination) {
    global $xtpl;

    $a = rand(1, 10);
    $b = rand(1, 10);
    
    $xtpl->assign('title', 'Log In');
    $xtpl->assign('destination', $destination);
    $xtpl->assign('captcha_hash', md5(SIMPLEID_BASE_URL . ($a + $b)));
    $xtpl->assign('captcha', $a . " + " . $b);
    
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
    
    foreach ($rps as $realm => $rp) {
        $xtpl->assign('realm', htmlspecialchars($rp['realm']));
        $xtpl->assign('last_time', htmlspecialchars(strftime(SIMPLEID_DATE_TIME_FORMAT, $rp['last_time'])));
        $xtpl->assign('auto_release', ($rp['auto_release']) ? 'checked="checked"' : '');
        $xtpl->parse('main.frontpage.realm');
    }
    
    if (isset($user['sreg'])) {
        foreach ($user['sreg'] as $name => $value) {
            $xtpl->assign('name', htmlspecialchars($name));
            $xtpl->assign('value', htmlspecialchars($value));
            $xtpl->parse('main.frontpage.sreg');
        }
    }
    
    $xtpl->parse('main.frontpage');
    
    $xtpl->assign('title', 'Home Page');
    $xtpl->parse('main');
    $xtpl->out('main');
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
