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

use \InvalidArgumentException;
use SimpleID\Util\Events\UIBuildEvent;
use SimpleID\Util\Forms\FormBuildEvent;

/**
 * An event used to build the login form.
 * 
 * This class is derived from `FormBuildEvent` with the additional
 * 
 */
class LoginFormBuildEvent extends FormBuildEvent {
    const A_REGION = 1;
    const DEFAULT_REGION = 'default';
    const AFTER_BUTTONS_REGION = 'after_buttons';

    /**
     * {@inheritdoc}
     */
    public function addBlock(string $id, string $content, int $weight = 0, array $additional = []): UIBuildEvent {
        if (!isset($additional['region'])) $additional['region'] = self::DEFAULT_REGION;

        return parent::addBlock($id, $content, $weight, $additional);
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
}

?>