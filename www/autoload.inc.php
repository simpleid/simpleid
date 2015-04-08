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
    $info = autoload_get_module_info($class);
    if (isset($info['file']) && file_exists($info['file'])) {
        require $info['file'];
    }
    return;
});

/**
 * Retrieves information on a SimpleID module
 *
 * @param string $name the fully qualified class name of the module
 */
function autoload_get_module_info($class) {
    static $class_map = array(
        'SimpleID\\' => array(
            'base_dir' => '/core/',
            'ext' => false,
        ),
        'SimpleID\\Modules\\' => array(
            'base_dir' => '/site/',
            'ext' => true,
        ),
        'SimpleID\\Upgrade\\' => array(
            'base_dir' => '/upgrade/',
            'ext' => false
        )
    );

    $results = array();

    $class = ltrim($class, '\\');

    foreach ($class_map as $prefix => $params) {
        $prefix_length = strlen($prefix);

        if (strncmp($prefix, $class, $prefix_length) !== 0) continue;

        $results['relative_class'] = substr($class, $prefix_length);

        if ($params['ext']) {
            $results['ext'] = strtolower(substr($results['relative_class'], 0, strncmp('\\', $results['relative_class'], 1) + 1));
            $ext = $results['ext'] . '/';
        } else {
            $ext = '';
        }
        $results['dir'] = __DIR__ . $params['base_dir'] . $ext;
        $results['file'] = $results['dir'] . str_replace('\\', '/', $results['relative_class']) . '.php';
    }

    return $results;
}

?>