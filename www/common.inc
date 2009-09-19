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
 * Common functions used by SimpleID, and the implementation of extensions.
 *
 * @package simpleid
 * @filesource
 */
 
/**
 * Sets a message to display to the user on the rendered SimpleID page.
 *
 * @param string $msg the message to set
 */
function set_message($msg) {
    global $xtpl;
    
    $xtpl->assign('message', $msg);
    $xtpl->parse('main.message');
}

/**
 * Provides an HTML-based redirection form for OpenID messages.
 *
 * @param string $url the location to which the user agent is redirected
 * @param mixed $message the OpenID message to include in the redirection
 * request.
 */
function redirect_form($url, $message) {
    global $xtpl;
    
    // Preserve GET parameters in url
    $parts = parse_url($url);
    $query = $parts['query'];
    if ($query) {
        $parts = explode('&', $query);
        foreach ($parts as $part) {
            list($key, $value) = explode('=', $part);
            $xtpl->assign('name', htmlspecialchars($key, ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('value', htmlspecialchars(urldecode($value), ENT_QUOTES, 'UTF-8'));
            $xtpl->parse('main.redirect.parameter');
        }
    }
    foreach ($message as $key => $value) {
        if ($key) {
            $xtpl->assign('name', htmlspecialchars($key, ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('value', htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
            $xtpl->parse('main.redirect.parameter');
        }
    }

    $xtpl->assign('url', $url);
    $xtpl->assign('title', 'Redirecting...');
    $xtpl->assign('page_class', 'dialog-page');
    
    $xtpl->parse('main.redirect');
    $xtpl->parse('main');
    
    $xtpl->out('main');
    
    exit;
}

/**
 * Displays a fatal error message and exits.
 *
 * @param string $error the message to set
 */
function indirect_fatal_error($error) {
    global $xtpl;
    
    set_message($error);
    
    $xtpl->parse('main');
    $xtpl->out('main');
    exit;
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
function is_https() {
    return (isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] == 'on'))
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && (strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) == 'https'))
        || (isset($_SERVER['HTTP_FRONT_END_HTTPS']) && ($_SERVER['HTTP_FRONT_END_HTTPS'] == 'on'));
}

/**
 * Serialises a variable for inclusion as a URL parameter.
 *
 * @param mixed $data the data to serialise
 * @return string serialised data
 */
function pickle($data) {
    return base64_encode(gzcompress(serialize($data)));
}

/**
 * Deserialises data specified in a URL parameter as a variable.
 *
 * @param string $pickle the serialised data
 * @return mixed the deserialised data
 */
function unpickle($pickle) {
    return unserialize(gzuncompress(base64_decode($pickle)));
}

/**
 * Obtains the URI of the current request, given a base URI.
 *
 * @param string $base the base URI
 * @return string the request URI
 */
function get_request_uri($base) {
    $i = strpos($base, '//');
    $i = strpos($base, '/', $i + 2);
    
    if ($i === false) {
        return $base . $_SERVER['REQUEST_URI'];
    } else {
        return substr($base, 0, $i) . $_SERVER['REQUEST_URI'];
    }
    
}

/**
 * Obtains a SimpleID URL.  URLs produced by SimpleID should use this function.
 *
 * @param string $query a properly encoded query string
 * @return string the url
 *
 * @since 0.7
 */
function simpleid_url($query = '') {
    // Make sure that the base has a trailing slash
    if ((substr(SIMPLEID_BASE_URL, -1) == '/') || (substr(SIMPLEID_BASE_URL, -9) == 'index.php')) {
        $url = SIMPLEID_BASE_URL;
    } else {
        $url = SIMPLEID_BASE_URL . '/';
    }
    if ($query == '') return $url;
    $url .= 'index.php?' . $query;
    return $url;
}

/**
 * Obtains a form token given a form ID.
 *
 * Form tokens are used in SimpleID forms to guard against cross-site forgery
 * attacks.
 *
 * @param string $id the form ID
 * @return string a form token
 */
function get_form_token($id) {
    global $user;

    if (store_get('site-token') == NULL) {
        $site_token = mt_rand();
        store_set('site-token', $site_token);
    } else {
        $site_token = store_get('site-token');
    }
    
    if ($user == NULL) {
        return md5($id . $site_token);
    } else {
        return md5(session_id() . $id . $site_token);
    }
}

/**
 * Checks whether a form token is valid
 *
 * @param string $token the token returned by the user agent
 * @param string $id the form ID
 * @return bool true if the form token is valid
 */
function validate_form_token($token, $id) {
    global $user;
    
    $site_token = store_get('site-token');
    
    if ($user == NULL) {
        return ($token == md5($id . $site_token));
    } else {
        return ($token == md5(session_id() . $id . $site_token));
    }
}

/* ------- SimpleID extension support ---------------------------------------- */

/**
 * Initialises the extension mechanism.  This function looks up the extensions
 * to load in the {@link SIMPLEID_EXTENSIONS} constants, loads them, then
 * calls the ns hook.
 */
function extension_init() {
    global $extensions;
    global $ns_to_extension;
    
    $extensions = preg_split('/,\s*/', SIMPLEID_EXTENSIONS);
    
    foreach ($extensions as $extension) {
        include_once 'extensions/' . $extension . '/' . $extension . '.extension.inc';
    }
}

/**
 * Invokes a hook in all the loaded extensions.
 *
 * @param string $function the name of the hook to call
 * @param mixed $args the arguments to the hook
 * @return array the return values from the hook
 */
function extension_invoke_all() {
    global $extensions;
    
    $args = func_get_args();
    $function = array_shift($args);
    $return = array();
    
    foreach ($extensions as $extension) {
        if (function_exists($extension . '_' . $function)) {
            log_debug('extension_invoke_all: ' . $extension . '_' . $function);
            $result = call_user_func_array($extension . '_' . $function, $args);
            if (isset($result) && is_array($result)) {
                $return = array_merge($return, $result);
            } elseif (isset($result)) {
                $return[] = $result;
            } 
        }
    }
    
    return $return;
}

/**
 * Invokes a hook in a specified extension.
 *
 * @param string $extension the extension to call
 * @param string $function the name of the hook to call
 * @param mixed $args the arguments to the hook
 * @return mixed the return value from the hook
 */
function extension_invoke() {
    $args = func_get_args();
    $extension = array_shift($args);
    $function = array_shift($args);
    
    if (function_exists($extension . '_' . $function)) {
        log_debug('extension_invoke: ' . $extension . '_' . $function);
        return call_user_func_array($extension . '_' . $function, $args);
    }
}

/**
 * Returns an array of currently loaded extensions.
 *
 * @param array a list of the names of the currently loaded extensions.
 */
function get_extensions() {
    global $extensions;
    
    return $extensions;
}
?>
