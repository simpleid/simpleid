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
        $this->filter('attr', static::class . '::instance()->attr');
        $this->filter('json', static::class . '::instance()->json');
    }

    /**
     * Filter to create an HTML attribute.
     * 
     * The output should be fed through a `raw` filter to prevent double-escaping.
     * 
     * @param mixed $val the attribute value
     * @param string $name the name of the attribute
     * @return string
     */
    public function attr(mixed $val = null, string $name = null): string {
        if (($val == null) || ($val == false)) return '';
        if ($val === true) return $this->esc($name);
        return $this->esc($name) . '="' . $this->esc($val) . '"';
    }

    /**
     * Filter to encode JSON.
     * 
     * This function uses `json_encode()` to encode the data as JSON. However,
     * it provides additional safety features so that they can be embedded
     * directly within `<script>` tags, including:
     * 
     * - if the input data is a single string, convert the double quotes to
     *   single quotes
     * - wrapping arrays and objects with `JSON.parse()`
     * 
     * The output should be fed through a `raw` filter to prevent double-escaping.
     * 
     * @param mixed $data the data to be converted
     * @return string
     */
    public function json(mixed $data = null): string {
        $json_flags = JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT | JSON_THROW_ON_ERROR;
        $json = json_encode($data, $json_flags);

        if (is_null($data) || is_numeric($data) || is_bool($data)) {
            // Simple types - return directly
            return $json;
        } elseif (is_string($data)) {
            // String - change quotation marks
            return "'" . substr($json, 1, -1) . "'";
        } elseif (($json == '[]') || ($json == '{}')) {
            // Empty object or array, return directly
            return $json;
        } else {
            // Complex type, wrap JSON parse
            $json = json_encode($json, $json_flags);
            return 'JSON.parse(\'' . substr($json, 1, -1) . '\')';
        }
    }
}

?>