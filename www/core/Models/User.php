<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2025
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

namespace SimpleID\Models;

use \Base;
use \Serializable;
use SimpleID\ModuleManager;
use SimpleID\Store\Storable;
use SimpleID\Util\ArrayWrapper;
use SimpleID\Util\OpaqueIdentifier;
use SimpleID\Util\Events\BaseDataCollectionEvent;
use SimpleID\Base\UserModule;

/**
 * Represents a SimpleID user
 */
class User extends ArrayWrapper implements Serializable, Storable {

    const ACTIVITY_LOG_SIZE = 10;

    /** @var string the user ID */
    protected $uid;

    /** @var array<string, array<string, mixed>> the activity log */
    protected $activities = [];

    /** @var array<string, array<string, mixed>> */
    public $clients = [];

    /**
     * @param array<string, mixed> $data
     */
    public function __construct($data = [ 'openid' => [] ]) {
        parent::__construct($data);
    }

    /**
     * Determines whether the user is an administrator
     *
     * @return bool true if the user is an administrator
     */
    public function isAdministrator() {
        return ($this->container['administrator']);
    }

    /**
     * Determines whether the user has a local OpenID identity
     *
     * @return bool true if the user has a local OpenID identity
     */
    public function hasLocalOpenIDIdentity() {
        return isset($this->container['openid']['identity']);
    }

    /**
     * Returns the user's local OpenID identity
     *
     * @return string the user's local OpenID identity
     */
    public function getLocalOpenIDIdentity() {
        return ($this->hasLocalOpenIDIdentity()) ? $this->container['openid']['identity'] : null;
    }

    /**
     * Generates a pairwise identity for this user, based on a specified
     * sector identifier.
     *
     * A *pairwise identity* is an opaque string that is unique to one or more clients
     * (identified by a common `$sector_identifier` parameter) which identifies the
     * user to those clients.  Issuing a pairwise identity means that the user's
     * SimpleID user name is not exposed to the clients.
     *
     * @param string $sector_identifier the client's sector identifier.
     * @return string the pairwise identity
     */
    public function getPairwiseIdentity($sector_identifier) {
        $opaque = new OpaqueIdentifier();
        return 'pwid:' . $opaque->generate($sector_identifier . ':' . $this->uid);
    }

    /**
     * Returns a display name for the user.  The display name is worked
     * out based on the data available.
     *
     * @return string the display name
     */
    public function getDisplayName() {
        if (isset($this->container['userinfo']['name'])) return $this->container['userinfo']['name'];
        if (isset($this->container['userinfo']['given_name']) && isset($this->container['userinfo']['family_name']))
            return $this->container['userinfo']['given_name'] . ' ' . $this->container['userinfo']['family_name'];
        return $this->uid;
    }

    /**
     * Add an entry to the user's recent activity log.
     *
     * The recent activity log contains the most recent authentication
     * activity performed by or on behalf of the user.  This includes instances
     * where the user manually logged into SimpleID, or where a client
     * requested authentication or authorisation from the user
     *
     * @param string $id the ID of the agent creating the activity - this could
     * be the user agent ID assigned by SimpleID (in case of user logins) or
     * the client ID
     * @param array<string, mixed> $data additional data
     * @return void
     */
    public function addActivity($id, $data) {
        $this->activities[$id] = $data;
        uasort($this->activities, function($a, $b) {
            if ($a['time'] == $b['time']) { return 0; } return ($a['time'] < $b['time']) ? 1 : -1;
        });
        if (count($this->activities) > self::ACTIVITY_LOG_SIZE) {
            $this->activities = array_slice($this->activities, 0, self::ACTIVITY_LOG_SIZE);
        }
    }

    /**
     * Returns the user's recent activity log.
     *
     * @return array<string, array<string, mixed>> the activity log
     */
    public function getActivities() {
        return $this->activities;
    }

    public function offsetSet($offset, $value): void {
        switch ($offset) {
            case 'uid':
                $this->uid = $value;
                break;
            case 'display_name':
                return;
            case 'identity':
                $this->container['openid']['identity'] = $value;
                break;
            default:
                parent::offsetSet($offset, $value);
        }
    }

    public function offsetExists($offset): bool {
        switch ($offset) {
            case 'uid':
            case 'display_name':
                return true;
            case 'identity':
                return $this->hasLocalOpenIDIdentity();
            default:
                return parent::offsetExists($offset);
        }
    }

    /**
     * Implementation of ArrayAccess
     * 
     * Ideally we should provide a mixed return type here, but for PHP7 compatibility,
     * we add a ReturnTypeWillChange attribute instead.
     */
    #[\ReturnTypeWillChange]
    public function offsetGet($offset) {
        switch ($offset) {
            case 'uid':
                return $this->uid;
            case 'display_name':
                return $this->getDisplayName();
            case 'identity':
                // Retained for compatibility purposes
                $mod = UserModule::instance();
                return ($this->hasLocalOpenIDIdentity()) ? $this->getLocalOpenIDIdentity() : $mod->getCanonicalURL('user/' . rawurlencode($this['uid']));
            default:
                return parent::offsetGet($offset);
        }
    }

    /**
     * @param string|null $hidden_value
     * @return array<string, mixed>
     */
    private function toSecureArray($hidden_value = null) {
        $event = new BaseDataCollectionEvent('user_secret_data_paths');
        $copy = new ArrayWrapper($this->container);
        \Events::instance()->dispatch($event);
        $secret_paths = $event->getResults();
        if ($secret_paths == null) $secret_paths = [];
        $secret_paths[] = 'uid';
        foreach ($secret_paths as $path) {
            if ($hidden_value) {
                $copy->set($path, $hidden_value);
            } else {
                $copy->unset($path);
            }
        }
        return $copy->toArray();        
    }

    /**
     * {@inheritdoc}
     */
    public function serialize() {
        $f3 = Base::instance();
        return $f3->serialize($this->__serialize());
    }

    /**
     * PHP `__serialize` magic method.
     * 
     * @see https://www.php.net/manual/en/language.oop5.magic.php#object.serialize
     * @return array<string, mixed>
     */
    public function __serialize() {
        $result = [];
        foreach (get_object_vars($this) as $var => $value) {
            if ($var == 'container') {
                $result['container'] = $this->toSecureArray();
            } else {
                $result[$var] = $value;
            }
        }
        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($data) {
        $f3 = Base::instance();

        /** @var array<string, mixed> $array */
        $array = $f3->unserialize($data);
        $this->__unserialize($array);
    }

    /**
     * PHP `__unserialize` magic method.
     * 
     * @see https://www.php.net/manual/en/language.oop5.magic.php#object.unserialize
     * @param array<string, mixed> $array
     * @return void
     */
    public function __unserialize($array) {
        foreach ($array as $var => $value) {
            $this->$var = $value;
        }
    }

    public function getStoreType() {
        return 'user';
    }


    public function getStoreID() {
        return $this->uid;
    }


    public function setStoreID($id) {
        $this->uid = $id;
    }

    /**
     * Returns a string representation of the user, with sensitive
     * information removed.
     * 
     * @return string
     */
    public function toString() {
        $result = [];
        foreach (get_object_vars($this) as $var => $value) {
            if ($var == 'container') {
                $result['container'] = $this->toSecureArray('[hidden]');
            } else {
                $result[$var] = $value;
            }
        }
        
        return print_r($result, true);
    }
}

?>
