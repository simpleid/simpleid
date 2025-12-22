<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2024
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

use Psr\EventDispatcher\StoppableEventInterface;
use SimpleID\Util\Events\StoppableEventTrait;
use SimpleID\Util\Events\UIBuildEvent;
use SimpleID\Util\Forms\FormBuildEvent;
use SimpleID\Util\UI\Template;

/**
 * An event used to build the login form.
 * 
 * This class is derived from `FormBuildEvent` with the additional
 * 
 */
class LoginFormBuildEvent extends FormBuildEvent implements StoppableEventInterface {
    use StoppableEventTrait;

    const IDENTITY_REGION = 'identity';
    const DEFAULT_REGION = 'default';
    const PASSWORD_REGION = 'password';  // JS popout
    const CREDENTIALS_REGION = 'credentials'; // identity, credentials, options
    const AFTER_BUTTONS_REGION = 'after_buttons';

    /** @var bool */
    protected $hasUIDBlock = false;

    /** @var array<string> */
    protected $UIDAutocompleteValues = [];

    /**
     * {@inheritdoc}
     */
    public function addBlock(string $id, string $content, int $weight = 0, array $additional = []): UIBuildEvent {
        if (!isset($additional['region'])) $additional['region'] = self::DEFAULT_REGION;

        return parent::addBlock($id, $content, $weight, $additional);
    }

    /**
     * @param array<string> $uid_autocomplete additional values to the autocomplete
     * attribute to be inserted into the login form
     * @return UIBuildEvent
     */
    public function addUIDBlock($uid_autocomplete = []): UIBuildEvent {
        // Check if user name block has already been added
        if (!$this->hasUIDBlock) {
            $this->hasUIDBlock = true;
            $tpl = Template::instance();
            return $this->addBlock('auth_uid', $tpl->render('auth_uid.html', false), 0, [ 'region' => self::IDENTITY_REGION ]);
        }
        $this->addUIDAutocompleteValues($uid_autocomplete);
        return $this;
    }

    /**
     * Add values to the autocomplete attribute to be inserted into the user ID
     * field in the login form.
     * 
     * Note that this does not insert the user ID block.  To do that, call the
     * {@link addUIDBlock} function.
     * 
     * @param array<string> $uid_autocomplete additional values
     * @return void
     */
    public function addUIDAutocompleteValues($uid_autocomplete = []) {
        if (count($uid_autocomplete) > 0) $this->UIDAutocompleteValues = array_merge($this->UIDAutocompleteValues, $uid_autocomplete);
    }

    /**
     * Retrieves the blocks grouped by region, ordered by the
     * weight, from lowest to highest.
     * 
     * @return array<string, array<mixed>>
     */
    public function getBlocksGroupedByRegion(): array {
        $result = [];
        $block_data = $this->getBlocks();
        foreach ($block_data as $block) {
            /** @var string $region */
            $region = $block['region'];

            if (isset($result[$region])) {
                $result[$region][] = $block;
            } else {
                $result[$region] = [ $block ];
            }
        }
        return $result;
    }

    /**
     * @return array<string>
     */
    public function getUIDAutocompleteValues(): array {
        return $this->UIDAutocompleteValues;
    }
}

?>