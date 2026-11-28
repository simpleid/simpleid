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
 * XX
 * 
 * @phpstan-type _Action array{type: string, url: string, params: array<string, mixed>, confirm?: string, class?: string|array<string>}
 * @phpstan-type _UserCredential array{id: string, title: string, description?: string, first_time?: int, last_time?: int, actions: array<_Action>}
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
     * @param _Action $action
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
     * @param array<_UserCredential> $credentials
     */
    public function addUserCredentialList(string $id, string $title, int $mode, array $credentials, int $weight = 0) {
        $this->userCredentials[] = [
            '#data' => [
                'id' => $id,
                'title' => $title,
                'mode' => $mode,
                'credentials' => $credentials
            ],
            '#weight1' => $mode,
            '#weight2' => $weight
        ];
    }

    /**
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

    public function getUserCredentials() {
        uasort($this->userCredentials, [ $this, 'sortByTwoWeights' ]);
        return array_map(function($a) { return $a['#data']; }, $this->userCredentials);
    }

    protected function sortByTwoWeights($a, $b) {
        if ($a['#weight1'] == $b['#weight1']) { 
            if ($a['#weight2'] == $b['#weight2']) return 0;
            return ($a['#weight2'] < $b['#weight2']) ? -1 : 1;
        }
        return ($a['#weight1'] < $b['#weight1']) ? -1 : 1;
    }
}

?>