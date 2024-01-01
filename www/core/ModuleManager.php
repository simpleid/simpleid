<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2024
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

namespace SimpleID;

use \Prefab;
use \Base;
use Psr\Log\LogLevel;

/**
 * Manages SimpleID modules.
 *
 * This is a singleton class which is used to load modules specified in
 * the configuration file.  This class also provides functionality for
 * calling hooks.
 */
class ModuleManager extends Prefab {
    /** @var array<string, Module> array of all loaded modules */
    private $modules = [];

    /** @var Base */
    private $f3;

    /** @var \Psr\Log\LoggerInterface */
    private $logger;

    function __construct() {
        $this->f3 = Base::instance();
        $this->logger = $this->f3->get('logger');
    }

    /**
     * Loads a module.
     *
     * @param string $name the fully qualified class name of the module to load
     * @return void
     */
    public function loadModule($name) {
        $this->logger->log(LogLevel::INFO, 'SimpleID\ModuleManager->loadModule: ' . $name);

        if (isset($this->modules[$name])) return;
        
        $info = $this->getModuleInfo($name);
        $module = new $name();
        if ($module instanceof Module) $this->modules[$name] = $module;
        
        if (isset($info['asset_domain'])) {
            $this->f3->set('UI', $this->f3->get('UI') . ';' . $info['asset_dir']);
            $this->f3->set('LOCALES', $this->f3->get('LOCALES') . ';' . $info['asset_dir']);
        }
    }

    /**
     * Returns whether a specified module is loaded.
     *
     * @param string $name the fully qualified class name of the module
     * @return bool true if the module is loaded
     */
    public function isModuleLoaded($name) {
        return isset($this->modules[$name]);
    }

    /**
     * Returns a specified loaded module.
     *
     * @param string $name the fully qualified class name of the module to return
     * @return Module the module
     */
    public function getModule($name) {
        return $this->modules[$name];
    }

    /**
     * Returns a list of loaded modules
     *
     * @return array<string> an array of fully qualified class names of the loaded
     * modules
     */
    public function getModules() {
        return array_keys($this->modules);
    }

    /**
     * Initialises the loaded modules.
     * 
     * @return void
     */
    public function initModules() {
        $listeners = \Listeners::instance();

        foreach ($this->modules as $name => $module) {
            if (method_exists($name, 'init')) {
                $this->logger->log(LogLevel::DEBUG, 'SimpleID\ModuleManager->initModules: ' . $name);
                call_user_func([ $name, 'init' ], $this->f3);
            }
            $listeners->map($module);
        }
    }

    /**
     * Retrieves information on a SimpleID module
     *
     * @param string $class the fully qualified class name of the module
     * @return array<string, string>
     */
    public function getModuleInfo($class) {
        $loader = $this->f3->get('class_loader');
        $root_dir = strtr(dirname(__DIR__), '\\', '/'); // Cross-platform way of getting a parent directory

        $results = [];

        $class_file = $loader->findFile($class);
        $class_dir = strtr(dirname($class_file), '\\', '/');

        if (strncmp($root_dir, $class_dir, strlen($root_dir)) === 0) {
            $relative_dir = substr($class_dir, strlen($root_dir) + 1);
            list ($base_dir, $module_dir, $dummy) = explode('/', $relative_dir, 3);

            switch ($base_dir) {
                case 'core':
                    break;
                case 'upgrade':
                    $results['asset_dir'] = $base_dir . '/';
                    $results['asset_domain'] = $base_dir;
                    break;
                case 'site':
                    $results['asset_dir'] = $base_dir . '/' . $module_dir . '/';
                    $results['asset_domain'] = $module_dir;
                    break;
            }
        }

        $results['file'] = $class_file;
        $results['dir'] = $class_dir;

        return $results;
    }
}

?>