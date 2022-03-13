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

use \Spyc;
use SimpleID\Models\User;
use SimpleID\Models\Client;

/**
 * A data store module that uses the file system for all of
 * its storage requirements.
 */
class DefaultStoreModule extends StoreModule {

    protected $config;

    public function __construct() {
        parent::__construct();
        $this->config = $this->f3->get('config');

        $this->checkConfig();
    }

    protected function checkConfig() {
        if (!is_dir($this->config['identities_dir'])) {
            $this->logger->log(\Psr\Log\LogLevel::CRITICAL, 'Identities directory not found.');
            $this->f3->error(500, $this->f3->get('intl.store.identity_not_found', 'http://simpleid.org/docs/2/installing/'));
        }

        if (!is_dir($this->config['store_dir']) || !is_writeable($this->config['store_dir'])) {
            $this->logger->log(\Psr\Log\LogLevel::CRITICAL, 'Store directory not found or not writeable.');
            $this->f3->error(500, $this->f3->get('intl.store.store_not_found', 'http://simpleid.org/docs/2/installing/'));
        }
    }

    public function getStores() {
        return [ 'user:default', 'client:default', 'keyvalue:default' ];
    }

    public function find($type, $criteria, $value) {
        switch ($type) {
            case 'user':
                return $this->findUser($criteria, $value);
        }
        return null;
    }

    public function exists($type, $id) {
        switch ($type) {
            case 'client':
                return $this->hasClient($id);
            case 'user':
                return $this->hasUser($id);
            default:
                return $this->hasKeyValue($type, $id);
        }
    }

    public function read($type, $id) {
        switch ($type) {
            case 'client':
                return $this->readClient($id);
            case 'user':
                return $this->readUser($id);
            default:
                return $this->readKeyValue($type, $id);
        }
    }

    public function write($type, $id, $value) {
        switch ($type) {
            case 'client':
                return $this->writeClient($id, $value);
            case 'user':
                // user settings are written using the keyvalue:write store
                return;
            default:
                return $this->writeKeyValue($type, $id, $value);
        }

    }

    public function delete($type, $id) {
        switch ($type) {
            default:
                return $this->deleteKeyValue($type, $id);
        }
    }

    /**
     * Finds a user
     *
     * @param string $criteria the criteria name
     * @param string $value the criteria value
     * @return User|null the item or null if no item is found
     */
    protected function findUser($criteria, $value) {
        $cache = \Cache::instance();
        $index = $cache->get('users_' . rawurldecode($criteria) . '.storeindex');
        if ($index === false) $index = [];
        if (isset($index[$value])) return $index[$value];

        $result = NULL;
        
        $dir = opendir($this->config['identities_dir']);
        
        while (($file = readdir($dir)) !== false) {
            $filename = $this->config['identities_dir'] . '/' . $file;
            
            if (is_link($filename)) $filename = readlink($filename);
            if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.user\.yml$/', $file, $matches))) continue;
            
            $uid = $matches[1];
            $test_user = $this->readUser($uid);

            $test_value = $test_user->pathGet($criteria);
        
            if ($test_value !== null) {
                if (is_array($test_value)) {
                    foreach ($test_value as $test_element) {
                        if (trim($test_element) != '') $index[$test_element] = $uid;
                        if ($test_element == $value) $result = $uid;
                    }
                } else {
                    if (trim($test_value) != '') {
                        $index[$test_value] = $uid;
                        if ($test_value == $value) $result = $uid;
                    }
                }
            }
        }
            
        closedir($dir);

        $cache->set('users_' . rawurldecode($criteria) . '.storeindex', $index);
        
        return $result;
    }

    /**
     * Returns whether the user name exists in the user store.
     *
     * @param string $uid the name of the user to check
     * @return bool whether the user name exists
     */
    protected function hasUser($uid) {
        if ($this->isValidName($uid)) {
            $identity_file = $this->config['identities_dir'] . "/$uid.user.yml";
            return (file_exists($identity_file));
        } else {
            return false;
        }
    }

    /**
     * Loads user data for a specified user name.
     *
     * The user name must exist.  You should check whether the user name exists with
     * the {@link store_user_exists()} function
     *
     * @param string $uid the name of the user to load
     * @return User|null data for the specified user
     */
    protected function readUser($uid) {
        if (!$this->isValidName($uid) || !$this->hasUser($uid)) return null;
        
        $identity_file = $this->config['identities_dir'] . "/$uid.user.yml";

        try {
            $data = Spyc::YAMLLoad($identity_file);
        } catch (\Exception $e) {
            $this->logger->log(\Psr\Log\LogLevel::ERROR, 'Cannot read user file ' . $identity_file . ': ' . $e->getMessage());
            trigger_error('Cannot read user file ' . $identity_file . ': ' . $e->getMessage(), E_USER_ERROR);
        }
            
        return new User($data);
    }


    /**
     * Returns whether the client name exists in the client store.
     *
     * @param string $cid the name of the client to check
     * @return bool whether the client name exists
     */
    protected function hasClient($cid) {
        if ($this->isValidName($cid)) {
            $client_file = $this->config['identities_dir'] . "/$cid.client.yml";
            if (file_exists($client_file)) return true;

            $store_file = $this->config['store_dir'] . "/$cid.client";
            return (file_exists($store_file));
        } else {
            return false;
        }
    }

    /**
     * Loads client data for a specified client name.
     *
     * The client name must exist.  You should check whether the client name exists with
     * the {@link hasClient()} function
     *
     * @param string $cid the name of the client to load
     * @return Client|null data for the specified user
     */
    protected function readClient($cid) {
        if (!$this->isValidName($cid) || !$this->hasClient($cid)) return null;

        $store_file = $this->config['store_dir'] . "/$cid.client";
        
        if (file_exists($store_file)) {
            $client = $this->f3->mutex($store_file, function($f3, $store_file) {
                return $f3->unserialize(file_get_contents($store_file));
            }, [ $this->f3, $store_file ]);
        } else {
            $client = new Client();
        }

        $client_file = $this->config['identities_dir'] . "/$cid.client.yml";
        if (file_exists($client_file)) {
            try {
                $data = Spyc::YAMLLoad($client_file);
            } catch (\Exception $e) {
                $this->logger->log(\Psr\Log\LogLevel::ERROR, 'Cannot read client file ' . $client_file . ' :' . $e->getMessage());
                trigger_error('Cannot read client file ' . $client_file . ' :' . $e->getMessage(), E_USER_ERROR);
            }

            if ($data != null) $client->loadData($data);
        }

        $client->cid = $cid;
        
        return $client;
    }

    /**
     * Saves client data for a specific client name.
     *
     * This data is stored in the client store file.
     *
     * @param string $cid the name of the client
     * @param Client $client the data to save
     */
    protected function writeClient($cid, $client) {
        if (!$this->isValidName($cid)) {
            trigger_error("Invalid client name for filesystem store", E_USER_ERROR);
            return;
        }
        
        $store_file = $this->config['store_dir'] . "/$cid.client";
        $this->f3->mutex($store_file, function($f3, $store_file, $client) {
            $file = fopen($store_file, 'w');
            fwrite($file, $f3->serialize($client));
            fclose($file);
        }, [ $this->f3, $store_file, $client ]);
    }

    /**
     * Returns whether a key-value item exists.
     *
     * @param string $type the item type
     * @param string $name the name of the key-value item to return
     * @return bool the value of the key-value item
     *
     */
    protected function hasKeyValue($type, $name) {
        $file = $this->getKeyValueFile($type, $name);
        return file_exists($file);
    }


    /**
     * Loads a key-value item.
     *
     * @param string $type the item type
     * @param string $name the name of the key-value item to return
     * @return mixed the value of the key-value item
     *
     */
    protected function readKeyValue($type, $name) {
        if (!$this->isValidName($name) || !$this->hasKeyValue($type, $name)) return null;
        $file = $this->getKeyValueFile($type, $name);
        return $this->f3->mutex($file, function($f3, $file) {
            return $f3->unserialize(file_get_contents($file));
        }, [ $this->f3, $file ]);
        
    }

    /**
     * Saves a key-value item.
     *
     * @param string $type the item type
     * @param string $name the name of the key-value item to save
     * @param mixed $value the value of the key-value item
     *
     */
    protected function writeKeyValue($type, $name, $value) {
        if (!$this->isValidName($name . '.' . $type)) {
            trigger_error("Invalid name for filesystem store", E_USER_ERROR);
            return;
        }

        $file = $this->getKeyValueFile($type, $name);
        $this->f3->mutex($file, function($f3, $file, $value) {
            file_put_contents($file, $f3->serialize($value), LOCK_EX);
        }, [ $this->f3, $file, $value ]);
    }

    /**
     * Deletes a key-value item.
     *
     * @param string $type the item type
     * @param string $name the name of the setting to delete
     *
     */
    protected function deleteKeyValue($type, $name) {
        if (!$this->isValidName($name . '.' . $type)) {
            trigger_error("Invalid name for filesystem store", E_USER_ERROR);
            return;
        }

        $file = $this->getKeyValueFile($type, $name);
        $this->f3->mutex($file, function() use ($file) { unlink($file); });
    }

    /**
     * Determines whether a name is a valid name for use with this store.
     *
     * For file system storage, a name is not valid if it contains either a
     * directory separator (i.e. / or \).
     *
     * @param string $name the name to check
     * @return boolean whether the name is valid for use with this store 
     *
     */
    protected function isValidName($name) {
        return preg_match('!\A[^/\\\\]*\z!', $name);
    }

    private function getKeyValueFile($type, $name) {
        $name = str_replace('%7E', '~', rawurlencode($name));
        if (preg_match('/^\.+$/', $name)) $name = str_replace('.', '%2E', $name);
        return $this->config['store_dir'] . '/' . $name . '.' . $type;
    }
}

?>