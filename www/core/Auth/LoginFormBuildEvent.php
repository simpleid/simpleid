<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2024-2026
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
 * This class is derived from {@link SimpleID\Util\Forms\FormBuildEvent}, which
 * uses {@link SimpleID\Util\UI\UIBuilder} to build the form.  This event uses
 * a `region` key in the `$additional` array in the {@link addBlock()} method
 * to associate each block with a *region*.  Blocks in each region are sorted
 * and displayed independently of each other.
 * 
 * The regions defined by this class, and their function, can be found in the
 * documentation of the constants below.
 * 
 */
class LoginFormBuildEvent extends FormBuildEvent implements StoppableEventInterface {
    use StoppableEventTrait;

    /**
     * Constant denoting the `identity` region.  The identity region contains a single
     * block to allow the user to specify an identifier (such as the user name), or
     * show the identifier if is already given.
     * 
     * Authentication modules that require an identifer to be given should call
     * the {@link showUIDBlock()} method.  Otherwise no blocks should be added
     * to this region.
     */
    const IDENTITY_REGION = 'identity';
    /**
     * Constant denoting the `password` region.  The password region is added by
     * the {@link PasswordAuthSchemeModule} module, to be rendered in the DOM
     * but hidden from the user unless it is required.  This allows browser
     * password managers to automatically fill in the password in the background.
     * 
     * No other blocks should be added to this region.
     */
    const PASSWORD_REGION = 'password';
    /**
     * Constant denoting the `default` region.  If a region is not specified when
     * adding the block, the block will be added to this region.
     * 
     * Note that blocks in the default region are rendered in the DOM, but
     * not always shown to the user. For example, if the user is able to choose
     * between multiple authentication methods, only the block associated with
     * selected method is shown to the user, while other blocks are hidden.
     * To always show a block, add it to the `options` region.
     */
    const DEFAULT_REGION = 'default';
    /**
     * Constant denoting the `options` region.  Blocks in this region are
     * rendered below the `default` region but above the submit button.
     */
    const OPTIONS_REGION = 'options';
    /**
     * Constant denoting the `secondary` region.  Blocks in this region
     * are always rendered below the default submit button.
     * 
     * If a block is added to this region, then a divider will be shown
     * in the login form.
     */
    const SECONDARY_REGION = 'secondary';

    /** @var bool */
    protected $hasUIDBlock = false;

    /** @var bool */
    protected $UIDBlockRendered = false;

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
     * Show the user ID block when presenting the login form, and optionally
     * add values to the `autocomplete` attribute in the user ID field.
     * 
     * @param array<string> $uid_autocomplete additional values to the autocomplete
     * attribute to be inserted into the login form
     * @return UIBuildEvent
     */
    public function showUIDBlock($uid_autocomplete = []): UIBuildEvent {
        $this->hasUIDBlock = true;

        if (count($uid_autocomplete) > 0) $this->UIDAutocompleteValues = array_merge($this->UIDAutocompleteValues, $uid_autocomplete);
        return $this;
    }

    /**
     * {@inheritdoc}
     * 
     * @return array<array<mixed>>
     */
    public function getBlocks(): array {
        // Check if user name block has already been added
        if (!$this->UIDBlockRendered) {
            $this->UIDBlockRendered = true;
            $tpl = Template::instance();
            $this->addBlock('auth_uid', $tpl->render('auth_uid.html', false), 0, [ 'region' => self::IDENTITY_REGION ]);
        }

        return parent::getBlocks();
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