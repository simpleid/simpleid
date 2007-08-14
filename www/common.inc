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

// 6.2.1. HTTP Redirect
function redirect_http($url, $encoded_message) {
    header('Status: 302 Found');
    header('Location: ' . $url . '?' . $encoded_message);
    exit;
}

// 6.2.2. HTML FORM Redirection
function redirect_form($url, $message) {
    global $xtpl;
    
    $items = explode("\n", $message);
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
    foreach ($items as $item) {
        list($key, $value) = explode(':', $item, 2);
        if ($key) {
            $xtpl->assign('name', htmlspecialchars($key));
            $xtpl->assign('value', htmlspecialchars($value));
            $xtpl->parse('main.redirect.parameter');
        }
    }

    $xtpl->assign('url', $url);
    
    $xtpl->parse('main.redirect');
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

?>
