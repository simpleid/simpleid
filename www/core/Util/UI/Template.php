<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2023
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

namespace SimpleID\Util\UI;

use \Template as F3Template;

/**
 * An extension to the Fat-Free Framework `Template` class to
 * support attachments.
 *
 */
class Template extends F3Template implements AttachmentManagerInterface {
    use AttachmentManagerTrait;

    public function __construct() {
        parent::__construct();

        // $this->attachments comes from AttachmentManagerTrait
        // $this->fw comes from the Fat-Free View class
        if (!$this->fw->exists('attachments')) $this->fw->set('attachments', []);
        $this->attachments = &$this->fw->ref('attachments');

        // Register filters
        $this->filter('attr', self::class . '::instance()->attr');
    }

    public function attr(mixed $val = null, string $name = null): string {
        if (($val == null) || ($val == false)) return '';
        if ($val === true) return $this->esc($name);
        return $this->esc($name) . '="' . $this->esc($val) . '"';
    }
}

?>