<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2022
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

namespace SimpleID\Store;

use \Base;
use \Prefab;
use SimpleID\ModuleManager;
use SimpleID\Models\User;

/**
 * Singleton class that manages data storage.
 *
 * Each item that can be stored in SimpleID is identified using an
 * *item type* and an *identifier* unique to that type.  An item
 * is typically (but is not required to be) represented by a class
 * implementing the {@link Storable} interface.
 *
 * A mechanism used to store or retrieve an item (such as a file
 * system, a LDAP directory or a database) is called a *store*.
 * A store is identified using the format <var>name</var>:<var>method</var>,
 * where <var>name</var> represents the item type or the group of item
 * types it is able to store or retrieve and <var>method</var> represents
 * the operation (`read` or `write`).  `default` is used as a special
 * method to denote the store to use when no other stores with `read` or
 * `write` operation can be found for that store name.
 *
 * A *store module* is a subclass of {@link StoreModule} that
 * implements one or more stores.  The stores that a store module implements
 * can be found using the {@link StoreModule::getStores()} method.
 *
 * The use of stores means that multiple store modules can be enabled, with
 * each handling a particular store, with a `default` store acting as a
 * fallback for each type.
 *
 * Currently the following stores a defined.  The stores in bold are
 * required to be implemented for SimpleID to function.
 *
 * - **user:read** (read from a directory of users)
 * - user:write
 * - **client:read** (read client data)
 * - **client:write** (write client data)
 * - **keyvalue:read** (read key-value data)
 * - **keyvalue:write** (write key-value data)
 *
 * These stores are implemented by {@link DefaultStoreModule}.
 *
 * Data can be loaded and saved using the methods `loadXX()`, `saveXX()`
 * `deleteXX()`, where XX is the item type in camel case.  These
 * are implemented using the magic method {@link __call()}, which
 * calls {@link load()}, {@link save()} and {@link delete()}.
 *
 * ## Special cases
 *
 * - **Users.**  User data are split across two stores: user:read/write
 *   and user_cfg:read/write (which defaults to keyvalue:read/write).  user_cfg
 *   is the store used by SimpleID to write its own data on users (e.g. user
 *   preferences and past activity).  Splitting user data across two stores
 *   enable the use of a read-only directory service (e.g. LDAP) for directory
 *   information (user:read) while using another storage mechanism for
 *   preferences (user_cfg:read/write).
 *
 * - **Settings.** Convenience methods {@link getSetting()}, {@link setSetting()}
 *   and {@link deleteSetting()} are provided.
 *
 */
class StoreManager extends Prefab {
    /** @var array a mapping between the identifier of a store and its store module */
    protected $stores = [];

    private $cache = [];

    /** @var string a space delimited list of stores that must be implemented */
    const REQUIRED_STORES = 'user:read client:read client:write keyvalue:read keyvalue:write';

    /**
     * Adds a store module to the store manager.
     *
     * This is called by {@link SimpleID\Store\StoreModule::__construct()}, so this
     * function should generally not needed to be called
     *
     * @param StoreModule $module a store module
     * @param array $stores an array of stores that the module supports
     */
    public function addStore($module, $stores) {
        foreach ($stores as $store) {
            $this->stores[$store] = $module;
        }
    }

    /**
     * Checks whether a store module exists to handle each store.
     *
     * This function triggers a PHP error if there is a store that
     * is not handled by at least one store module.
     */
    public function checkStores() {
        foreach (explode(' ', self::REQUIRED_STORES) as $store) {
            if ($this->getStore($store) === null) {
                trigger_error("No store for $store");
            }
        }
    }

    /**
     * Finds a generic item based on specified criteria.  The criteria should identify
     * a single item uniquely.
     *
     * The criteria name is specified as a FatFree path.
     *
     * @param string $type the item type
     * @param string $criteria the criteria name
     * @param string $value the criteria value
     * @return Storable the item or null if no item is found
     */
    public function find($type, $criteria, $value) {
        $store = $this->getStore($type . ':read');
        $id = $store->find($type, $criteria, $value);
        if ($id != null) return $this->load($type, $id);
        return null;
    }

    /**
     * Loads generic item data for a specified item ID.
     *
     * The item ID must exist.  You should check whether the item ID exists with
     * the {@link exists()} function
     *
     * @param string $type the item type
     * @param string $id the identifier of the item to load
     * @return Storable data for the specified item
     */
    public function load($type, $id) {
        $cache_name = $type . ':' . $id;

        if (!isset($this->cache[$cache_name])) {
            $store = $this->getStore($type . ':read');
            $storable = $store->read($type, $id);
            if ($storable == null) return null;

            $storable->setStoreID($id);

            $this->cache[$cache_name] = $storable;
        }
        
        return $this->cache[$cache_name];
    }

    /**
     * Saves item data.
     *
     * This data is stored in the store file.
     *
     * @param string $type the item type
     * @param Storable $item the item to save
     *
     * @since 0.7
     */
    public function save($type, $item) {
        $this->cache[$type . ':' . $item->getStoreID()] = $item;

        $store = $this->getStore($type . ':write');
        $store->write($type, $item->getStoreID(), $item);
    }

    /**
     * Deletes item data.
     *
     * This data is stored in the store file.
     *
     * @param string $type the item type
     * @param Storable $item the item to delete
     */
    public function delete($type, $item) {
        $cache_name = $type . ':' . $item->getStoreID();
        $store = $this->getStore($type . ':write');
        if (isset($this->cache[$cache_name])) unset($this->cache[$cache_name]);
        $store->delete($type, $item->getStoreID());
    }

    /**
     * Loads a user.
     *
     * @param string $uid the user ID
     * @return \SimpleID\Models\User the user or null
     */
    public function loadUser($uid) {
        /** @var \SimpleID\Models\User $user */
        $user = $this->load('user', $uid);
        if ($user == null) return null;

        $user_config = $this->load('user_cfg', $uid);
        if ($user_config != null) {
            $user->loadData($user_config);
        }

        return $user;
    }

    /**
     * Saves a user.
     * 
     * @param \SimpleID\Models\User $user the user to save
     */
    public function saveUser($user) {
        if ($this->getStore('user:write', false) != null) {
            $this->save('user', $user);
        } else {
            $this->save('user_cfg', $user);
        }
    }

    /**
     * Loads a client, recasted to a specified class if required.
     *
     * `$class_name` must be a subclass of {@link SimpleID\Models\Client}.  If `$class_name` is
     * null, then the original class saved with the client is returned.
     *
     * @param string $cid the client ID
     * @param string $class_name the name of the class in which the data is
     * to be cast, nor null
     * @return \SimpleID\Models\Client the client or null
     */
    public function loadClient($cid, $class_name = null) {
        /** @var \SimpleID\Models\Client $client */
        $client = $this->load('client', $cid);
        if ($client == null) return null;

        if (($class_name == null) || !is_subclass_of($class_name, get_class($client), true)) {
            return $client;
        } else {
            $new_client = new $class_name($client->toArray());
            $new_client->loadFieldsFrom($client);
            return $new_client;
        }
    }

    /**
     * Loads an application setting.
     *
     * @param string $name the name of the setting to return
     * @param mixed $default the default value to use if this variable has never been set
     * @return mixed the value of the setting
     *
     */
    public function getSetting($name, $default = NULL) {
        $cache_name = 'setting:' . $name;

        if (!isset($this->cache[$cache_name])) {
            $store = $this->getStore('keyvalue:read');

            if (!$store->exists('setting', $name)) return $default;
            $setting = $store->read('setting', $name);
            if ($setting === null) return $default;

            $this->cache[$cache_name] = $setting;
        }
        
        return $this->cache[$cache_name];
    }

    /**
     * Saves an application setting.
     *
     * @param string $name the name of the setting to save
     * @param mixed $value the value of the setting
     *
     */
    public function setSetting($name, $value) {
        $this->cache['setting:' . $name] = $value;

        $store = $this->getStore('keyvalue:write');
        $store->write('setting', $name, $value);
    }

    /**
     * Deletes an application setting.
     *
     * @param string $name the name of the setting to delete
     *
     */
    public function deleteSetting($name) {
        $cache_name = 'setting:' . $name;
        $store = $this->getStore('keyvalue:write');
        if (isset($this->cache[$cache_name])) unset($this->cache[$cache_name]);
        $store->delete('setting', $name);
    }

    /**
     * Magic method which calls {@link load()}, {@link save()} and {@link delete()}.
     *
     * @param string $method
     * @param array $args
     */
    public function __call($method, $args) {
        $f3 = Base::instance();
        list($verb, $type) = explode('_', $f3->snakecase($method), 2);
        if (method_exists($this, $verb)) {
            array_unshift($args, $type);
            return call_user_func_array([ $this, $verb ], $args);
        }
    }

    /**
     * Obtains a store module for a specified store.
     *
     * @param string $store the name of the store
     * @param bool $use_defaults if true, also search for default
     * stores
     * @return StoreModule the store module
     */
    protected function getStore($store, $use_defaults = true) {
        if (isset($this->stores[$store])) return $this->stores[$store];
        if (!$use_defaults) return null;

        list($type, $op) = explode(':', $store);
        $store = $type . ':default';

        if (isset($this->stores[$store])) return $this->stores[$store];
        if ($type != 'keyvalue') return $this->getStore('keyvalue:' . $op);

        return null;
    }
}

?>