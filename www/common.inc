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
 
function set_message($msg) {
    global $xtpl;
    
    $xtpl->assign('message', $msg);
    $xtpl->parse('main.message');
}

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

function indirect_fatal_error($error) {
    global $xtpl;
    
    set_message($error);
    
    $xtpl->parse('main');
    $xtpl->out('main');
    exit;
}

function normalize_url($url) {
  $normalized_url = $url;

  $normalized_url = preg_replace('!^(xri://|xri://\$ip\*|xri://\$dns\*)!', '', $normalized_url);
  
  if (stristr($url, '://') === FALSE) {
    $normalized_url = 'http://' . $url;
  }

  return $normalized_url;
}

function pickle($data) {
    return base64_encode(gzcompress(serialize($data)));
}

function unpickle($pickle) {
    return unserialize(gzuncompress(base64_decode($pickle)));
}

define('SIMPLEID_EXTENSIONS', 'sreg');

// For sreg 1.0 compatibility
$ns_to_alias = array("http://openid.net/extensions/sreg/1.1" => "sreg");
$ns_to_extension = array();

function extension_init() {
    global $extensions;
    global $ns_to_extension;
    
    $extensions = preg_split('/, */', SIMPLEID_EXTENSIONS);
    
    foreach ($extensions as $extension) {
        include_once $extension . ".inc";
        
        $ns_to_extension[extension_invoke($extension, 'ns')] = $extension;
    }
}

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
            } else if (isset($result)) {
                $return[] = $result;
            } 
        }
    }
    
    return $return;
}

function extension_invoke() {
    $args = func_get_args();
    $extension = array_shift($args);
    $function = array_shift($args);
    
    if (function_exists($extension . '_' . $function)) {
        return call_user_func_array($extension . '_' . $function, $args);
    }
}

function extension_get_request($ns, $request) {
    $alias = extension_get_alias($ns);
    $return = array();
    
    if ($request) {
        foreach ($request as $key => $value) {
            if (strpos($key, 'openid.' . $alias . '.') === 0) {
                $return[substr($key, strlen('openid.' . $alias . '.'))] = $value;
            }
        }
    }
    
    return $return;
}

function extension_get_alias($ns) {
    global $ns_to_alias;
    
    return $ns_to_alias[$ns];
}

function get_extensions() {
    global $extensions;
    
    return $extensions;
}
?>
