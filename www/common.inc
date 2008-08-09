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
            $xtpl->assign('name', htmlspecialchars($key));
            $xtpl->assign('value', htmlspecialchars(urldecode($value)));
            $xtpl->parse('main.redirect.parameter');
        }
    }
    foreach ($message as $key => $value) {
        if ($key) {
            $xtpl->assign('name', htmlspecialchars($key));
            $xtpl->assign('value', htmlspecialchars($value));
            $xtpl->parse('main.redirect.parameter');
        }
    }

    $xtpl->assign('url', $url);
    $xtpl->assign('title', 'Redirecting...');
    
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
 * @param string the base URI
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

/* ------- SimpleID extension support ---------------------------------------- */

// For sreg 1.0 compatibility
$ns_to_alias = array("http://openid.net/extensions/sreg/1.1" => "sreg");
$ns_to_extension = array();

/**
 * Initialises the extension mechanism.  This function looks up the extensions
 * to load in the {@link SIMPLEID_EXTENSIONS} constants, loads them, then
 * calls the ns hook.
 */
function extension_init() {
    global $extensions;
    global $ns_to_extension;
    
    $extensions = preg_split('/, */', SIMPLEID_EXTENSIONS);
    
    foreach ($extensions as $extension) {
        include_once $extension . ".inc";
        
        if (extension_invoke($extension)) {
            $ns_to_extension[extension_invoke($extension, 'ns')] = $extension;
        }
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
        return call_user_func_array($extension . '_' . $function, $args);
    }
}

/**
 * Filters an OpenID request to find keys specific to an extension, as specified
 * by the Type URI.
 *
 * For exmaple, if the extension has the Type URI http://example.com/ and the
 * alias example, this function will return an array of all the keys in the
 * OpenID request which starts with openid.example
 *
 * @param string $ns the Type URI of the extension
 * @param mixed $request the OpenID request
 * @return array the filtered request, with the prefix (in the example above,
 * <tt>openid.example.</tt>) stripped in the keys.
 */
function extension_get_request($ns, $request) {
    $alias = extension_get_alias($ns);
    $return = array();
    
    if ($request) {
        foreach ($request as $key => $value) {
            if ($key == 'openid.' . $alias) {
                $return['#default'] = $value;
            }
            if (strpos($key, 'openid.' . $alias . '.') === 0) {
                $return[substr($key, strlen('openid.' . $alias . '.'))] = $value;
            }
        }
    }
    
    return $return;
}

/**
 * Returns the OpenID alias for an extension, given a Type URI, based on the
 * alias definitions in the current OpenID request.
 *
 * @param string $ns the Type URI
 * @return string the alias
 */
function extension_get_alias($ns) {
    global $ns_to_alias;
    
    return $ns_to_alias[$ns];
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
