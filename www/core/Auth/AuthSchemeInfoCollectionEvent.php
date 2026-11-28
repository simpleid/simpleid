<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2026
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

namespace SimpleID\Auth;

use SimpleID\Util\Events\BaseEvent;

/**
 * Event dispatched to collect information on the logged-in user's
 * credentials, as well as options to add new credentials.
 * 
 * @phpstan-type _Action array{type: string, url: string, params?: array<string, mixed>, title?: string, confirm?: string, class?: string|array<string>}
 * @phpstan-type _UserCredential array{id: string, subtype?: string, title?: string, description?: string, first_time?: int, last_time?: int, actions?: array<_Action>}
 */
class AuthSchemeInfoCollectionEvent extends BaseEvent {

    const ACTION_TYPE_LINK = 'link';
    const ACTION_TYPE_FORM = 'form';
    const ACTION_TYPE_AJAX = 'ajax';

    /** @var array<array<mixed>> */
    protected $createCredentialTypes = [];

    /** @var array<array<mixed>> */
    protected $userCredentials = [];

    /**
     * Adds a credential type of the list of credentials that can be
     * created.
     * 
     * @param string $id an ID of the credential type - typically the name
     * of the authentication scheme module
     * @param string $title the title of the credential type to be presented
     * to the user
     * @param int $mode the mode constant from AuthModule where the credential is used, for sorting purposes
     * @param _Action $action the action to create the credential
     * @param int $weight the weight for sorting
     * @return void
     */
    public function addCreateCredentialTypeItem(string $id, string $title, int $mode, array $action, int $weight = 0) {
        $this->createCredentialTypes[] = [
            '#data' => [
                'id' => $id,
                'title' => $title,
                'mode' => $mode,
                'action' => $action
            ],
            '#weight1' => $mode,
            '#weight2' => $weight
        ];
    }

    /**
     * Adds a list of credentials that are currently saved for the user.
     * 
     * @param string $id an ID of the credential type - typically the name
     * of the authentication scheme module
     * @param string $title the title of the credential type to be presented
     * to the user
     * @param int $mode the mode constant from AuthModule where the credential is used, for sorting purposes
     * @param array<_UserCredential> $credentials a list of credentials for this
     * credential type
     * @param int $weight the weight for sorting
     * @param bool $allowMultiple whether multiple credentials are allowed to
     * be saved for this credential type
     * @return void
     */
    public function addUserCredentialList(string $id, string $title, int $mode, array $credentials, int $weight = 0, bool $allowMultiple = false) {
        $this->userCredentials[] = [
            '#data' => [
                'id' => $id,
                'title' => $title,
                'mode' => $mode,
                'credentials' => $credentials,
                'allow_multiple' => $allowMultiple
            ],
            '#weight1' => $mode,
            '#weight2' => $weight
        ];
    }

    /**
     * Returns a list of credentials that are able to be created.
     * 
     * @return array<array<mixed>>
     */
    public function getCreateCredentialTypeList(): array {
        $sort_by = function ($a, $b) {
            $result = $this->sortByTwoWeights($a, $b);
            if ($result == 0) {
                return strcmp($a['#data']['title'], $b['#data']['title']);
            }
            return $result;
        };

        uasort($this->createCredentialTypes, $sort_by);
        return array_values(array_map(function($a) { return $a['#data']; }, $this->createCredentialTypes));
    }

    /**
     * Returns a list of credentials that are currently saved.
     * 
     * @return array<array<mixed>>
     */
    public function getUserCredentials(): array {
        uasort($this->userCredentials, [ $this, 'sortByTwoWeights' ]);
        return array_values(array_map(function($a) { return $a['#data']; }, $this->userCredentials));
    }

    /**
     * Comparison function for where each item is an associative
     * array with weights specified by keys named `#weight1` and `#weight2`.
     * 
     * This function sorts the items by `#weight1`, and then
     * by weight two `#weight2`.
     * 
     * @param mixed $a
     * @param mixed $b
     */
    protected function sortByTwoWeights($a, $b): int {
        if ($a['#weight1'] == $b['#weight1']) { 
            if ($a['#weight2'] == $b['#weight2']) return 0;
            return ($a['#weight2'] < $b['#weight2']) ? -1 : 1;
        }
        return ($a['#weight1'] < $b['#weight1']) ? -1 : 1;
    }
}

?>