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

const CORE_MODULE_PREFIX = 'SimpleID\\';
const SITE_MODULE_PREFIX = 'SimpleID\\Modules\\';

spl_autoload_register(function ($class) {
    $info = autoload_get_module_info($class);
    if (isset($info['file']) && file_exists($info['file'])) {
        require $info['file'];
    }
    return;
});


function autoload_get_module_info($class) {
    static $core_length = 0;
    static $site_length = 0;

    if ($core_length == 0) $core_length = strlen(CORE_MODULE_PREFIX);
    if ($site_length == 0) $site_length = strlen(SITE_MODULE_PREFIX);

    $results = array();

    $class = ltrim($class, '\\');

    if (strncmp(CORE_MODULE_PREFIX, $class, $core_length) === 0) {
        $results['relative_class'] = substr($class, $core_length);
        $results['dir'] = __DIR__ . '/core/';
        $results['file'] = $results['dir'] . str_replace('\\', '/', $results['relative_class']) . '.php';
    } elseif (strncmp(SITE_MODULE_PREFIX, $class, $site_length) === 0) {
        $results['relative_class'] = substr($class, $site_length);
        $results['site'] = strtolower(substr($results['relative_class'], 0, strncmp('\\', $results['relative_class'], 1) + 1));
        $results['dir'] = __DIR__ . '/site/' . $results['site'] . '/';
        $results['file'] = $results['dir'] . str_replace('\\', '/', $results['relative_class']) . '.php';
    }
    return $results;
}

?>