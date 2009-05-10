<?php 
/*
 * SimpleWeb
 *
 * Copyright (C) Kelvin Mo 2009
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
 * $Id: common.inc 66 2008-09-13 04:54:52Z kmo $
 */

function simpleweb_run($routes, $request_path = NULL, $not_found_route = NULL) {
    if ($request_path == NULL) {
        // We take the request path from the request URI
        $request_path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        
        // Strip off all parts to the script file name
        $script_name = basename($_SERVER['SCRIPT_NAME']);
        $request_path = substr($request_path, strpos($request_path, $script_name) + strlen($script_name));
        
        $request_path = trim($request_path, '/');
    }
    
    foreach ($routes as $pattern => $route) {
        
        if (!isset($route)) return array($pattern, null);
        $regex = '#^' . trim($pattern, '/') . '$#i';
        
        if (!preg_match($regex, $request_path, $args) > 0) continue;
        
        $args = (count($args) > 1) ? array_slice($args, 1) : null;
        return _simpleweb_invoke($route, $args);
    }
    
    if ($not_found_route) return _simpleweb_invoke($not_found_route, array($request_path));
}

function _simpleweb_invoke($route, $args = array()) {
    if (strpos($route, '::') !== false) {
        list($class, $method) = split($route, '::', 2);
        return call_user_func_array(array($class, $method), $args);
    } elseif(strpos($route, '->') !== false) {
        list($class, $method) = split($route, '->', 2);
        $object &= new $class;
        return call_user_func_array(array($object, $method), $args);
    } else {
        return call_user_func_array($route, $args);
    }
}
?>
