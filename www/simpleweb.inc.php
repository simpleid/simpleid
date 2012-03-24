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
 * $Id$
 */

/**
 * Simpleweb is a minimalist web framework.  It is similar to {@link http://webpy.org web.py},
 * but in PHP.
 *
 * The key to Simpleweb is the <i>route array</i>.  The route array is an array that maps
 * URLs (called <i>patterns</i>) to PHP functions or methods (called <i>routes</i>).
 *
 * Patterns are regular expressions, which are tested against the URL one at a time.
 * Subpatterns (i.e. patterns within parentheses) are then passed on as arguments
 * to the route.
 *
 * Routes are either functions, static methods or object methods.  A function is
 * denoted by the function name.  A static method is denoted by the class name,
 * followed by :: then the method name.  An object method is denoted by the class
 * name, followed by -&gt; then the method name.  An instance of the class will be
 * created before an object method is called.
 *
 * An example of a routes array is given below:
 *
 * <code>
 * <?php
 * $routes = array(
 *     'a' => 'function1',
 *     'b/(.+)' => 'function2',   // arguments
 *     'c' => 'ClassA::method',   // static method
 *     'd' => 'ClassB->method',   // object method
 * );
 * ?>
 * </code>
 *
 * Once the route array is populated, the {@link simpleweb_run()} function
 * is then called to handle the URL.
 *
 * @package simpleweb
 * @since 0.7
 */

/**
 * Handles a supplied request, based on a set of routes.
 *
 * @param array $routes the routes array, as described in {@link simpleweb.inc this page}
 * @param string $request_path the request path against which the routes are applied.  If
 * NULL, then the request URI supplied by the web server will be used.
 * @param string $not_found_route the default route if none of the patterns match.  If
 * NULL, then an HTTP 404 error is raised
 * @return mixed the result from calling the route.
 *
 */
 
function simpleweb_run($routes, $request_path = NULL, $not_found_route = NULL) {
    if ($request_path == NULL) {
        // We take the request path from the request URI
        $request_path = $_SERVER['REQUEST_URI'];
        
        // Strip off all parts to the script file name.  Sadly, PHP is historically
        // buggy in its treatment of SCRIPT_NAME, so we need to try a few methods
        // to strip them
        $script_name = basename($_SERVER['SCRIPT_NAME']);
        $script_dir = dirname($_SERVER['SCRIPT_NAME']);
        
        if (strpos($request_path, $script_name) !== false) {
            $request_path = substr($request_path, strpos($request_path, $script_name) + strlen($script_name));
        } elseif ($script_dir != '/') {
            $request_path = str_replace($script_dir, '', $request_path);
        }
        
        $request_path = trim($request_path, '/');
    }
    
    // Strip off GET parameters when passed in SAPI CGI mode
    $request_path = strtok($request_path, '?');
    
    foreach ($routes as $pattern => $route) {
        
        if (!isset($route)) continue;
        $regex = '#^' . trim($pattern, '/') . '$#i';
        
        if (!preg_match($regex, $request_path, $args) > 0) continue;
        
        $args = (count($args) > 1) ? array_slice($args, 1) : array();
        return _simpleweb_invoke($route, $args);
    }
    
    if ($not_found_route) return _simpleweb_invoke($not_found_route, array($request_path));
    
    _simpleweb_not_found();
}

/**
 * Invokes a route.
 *
 * @param string $route the route
 * @param array $args the arguments
 * @return mixed the result from calling the route.
 */
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

/**
 * Displays a HTTP 404 Not Found error and exits.
 */
function _simpleweb_not_found() {
    if (substr(PHP_SAPI, 0, 3) === 'cgi') {
        header('Status: 404 Not Found');
    } else {
        header('HTTP/1.1 404 Not Found');
    }
    header('Content-Type: text/plain');
    
    print 'Not Found';
    
    exit;
}
?>
