<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014
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
 */

include_once 'vendor/autoload.php';

spl_autoload_register(function ($class) {
    $core_prefix = 'SimpleID\\';
    $core_length = strlen($core_prefix);
    $module_prefix = 'SimpleID\\Modules\\';
    $module_length = strlen($module_prefix);

    if (strncmp($core_prefix, $class, $core_length) === 0) {
        $relative_class = substr($class, $core_length);
        $file = __DIR__ . '/core/' . str_replace('\\', '/', $relative_class) . '.php';
        if (file_exists($file)) {
            require $file;
        }
    } elseif (strncmp($module_prefix, $class, $module_length) === 0) {
        $relative_class = substr($class, $module_length);
        $module_name = strtolower(substr($relative_class, 0, strncmp('\\', $relative_class, 1) + 1));
        $file = __DIR__ . '/modules/' . $module_name . '/' . str_replace('\\', '/', $relative_class) . '.php';
        if (file_exists($file)) {
            require $file;
        }
    }
    return;
});

$f3 = require('vendor/bcosca/fatfree/lib/base.php');

?>