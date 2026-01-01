<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2026
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

namespace SimpleID\Base;

use SimpleID\Util\Events\BaseEvent;

/**
 * An event to collect scope information.
 * 
 * Different identity protocols use the concept of *scope* to limit
 * the extent to which authorisation is provided by the user.  This
 * event is used to collect all the possible scopes that this
 * SimpleID installation can provide, as well as human-friendly
 * information on these scopes.
 * 
 * Scope information is categorised into *types*.  Generally each
 * identity protocol would have a separate type assigned.  Currently
 * the available types are:
 * 
 * - `openid` for the OpenID 1 and 2 protocols
 * - `oauth` for OAuth based protocols (including OpenID Connect)
 * 
 * Listeners should use {@link addScopeInfo()} to add scope information.
 */
class ScopeInfoCollectionEvent extends BaseEvent {
    /** @var array<string, array<string, mixed>> */
    protected $scope_info = [];

    /**
     * Add scope information.
     *
     * The scope information is arranged as an array, with the key being the
     * protocol specific name of the scope, and the value being an array of
     * protocol specific settings.  Commonly used settings include:
     *
     * - `description` - a description of the scope presented to the user in
     *   the consent page
     * - `weight` - used for sorting multiple scopes when presented to the
     *   user
     * - `claims` - in OpenID Connect, the claims available in the `userinfo`
     *   endpoint if granted
     * 
     * @param string $type the type of the scope information
     * @param array<string, array<string, mixed>> $scopes the scope information
     * @return void
     */
    public function addScopeInfo($type, $scopes) {
        $this->scope_info = array_merge_recursive($this->scope_info, [ $type => $scopes ]);
    }

    /**
     * Returns scopes for a particular type.
     * 
     * @param string $type the type of scopes to return
     * @return array<string> an array of scopes, or an empty array
     * if no scope information is found for this particular type
     */
    public function getScopesForType($type) {
        if (!isset($this->scope_info[$type])) return [];
        return array_keys($this->scope_info[$type]);
    }

    /**
     * Returns scope informations for a particular type.
     * 
     * @param string $type the type of scopes to return
     * @return array<string, mixed> an array containing scope information for the specified
     * type, or an empty array if no scope information is found for this
     * particular type
     */
    public function getScopeInfoForType($type) {
        return $this->scope_info[$type];
    }

    /**
     * Returns the entire registry of scope information.
     * 
     * The array returned is organised by type, with the name of the type
     * as the key, and the scope information (equivalent to calling
     * {@link getScopesForType()}) as the value.
     * 
     * @return array<string, array<string, mixed>> the scope information
     */
    public function getAllScopeInfo() {
        return $this->scope_info;
    }
}

?>
