<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2023-2024
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

use \Base;
use \Markdown;
use \Template as F3Template;
use SimpleID\Util\ArrayWrapper;

/**
 * An extension to the Fat-Free Framework `Template` class to
 * support attachments.
 *
 */
class Template extends F3Template implements AttachmentManagerInterface {
    use AttachmentManagerTrait;

    /** @var ArrayWrapper */
    protected $returnValues;

    public function __construct() {
        // tags are automatically registered here
        parent::__construct();

        $this->returnValues = new ArrayWrapper();

        // $this->attachments comes from AttachmentManagerTrait
        // $this->fw comes from the Fat-Free View class
        if (!$this->fw->exists('attachments')) $this->fw->set('attachments', []);
        $this->attachments = &$this->fw->ref('attachments');

        // Register filters
        $this->filter('attr', static::class . '::instance()->attr');
        $this->filter('js', static::class . '::instance()->js');
        $this->filter('markdown', static::class . '::instance()->markdown');
        $this->filter('html_to_text', static::class . '::instance()->html_to_text');
    }

    /**
     * Captures the output.
     * 
     * ```
     * <capture to="varname"><include href="foo"></capture>
     * ```
     * 
     * @param array $node the template node
     * @return string the compiled PHP code
     */
    public function _capture(array $node) {
        $attrib = $node['@attrib'];
        unset($node['@attrib']);

        if ($attrib['to'] && preg_match('/^[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*$/', $attrib['to'])) {
            return '<?php ob_start(); ?>'
                . $this->build($node)
                . '<?php $' . $attrib['to'] .' = ob_get_clean(); ?>';
        } else {
            return '';
        }
    }

    /**
     * Sets a return value.
     * 
     * ```
     * <return name="value">
     * ```
     * 
     * @param array $node the template node
     * @return string the compiled PHP code
     */
    public function _return(array $node) {
        $out = '';
        foreach ($node['@attrib'] as $key => $val) {
            $out .= '$this->setReturnValue(' . Base::instance()->stringify($key) . ', '.
                (preg_match('/\{\{(.+?)\}\}/',$val?:'')?
                    $this->token($val):
                    Base::instance()->stringify($val)).'); ';
        }
        return '<?php '.$out.'?>';
    }

    public function _mail_callout(array $node) {
        $callout_bg = '<?= (' . $this->token('@@lightmode.callout_bg') . ') ?>';
        $callout_text = '<?= (' . $this->token('@@lightmode.callout_text') . ') ?>';

        $out = '<div style="padding: 0 20px 20px;">';
        $out .= '<table align="center" role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: auto;">';
        $out .= '<tr>';
        $out .= '<td class="callout-td" style="background:' . $callout_bg . ';">';
        $out .= '<div class="callout-div" style="background: ' . $callout_bg . '; font-family: sans-serif; font-size: 21px; line-height: 21px; text-decoration: none; padding: 19px 23px; color: ' . $callout_text . ';">';
        $out .= $this->build($node);
        $out .= '</div></td>';
        $out .= '</tr>';
        $out .= '</table>';         
        $out .= '</div>';

        return $out;        
    }

    public function _mail_button(array $node) {
        $attrib = $node['@attrib'];
        unset($node['@attrib']);

        $button_bg = '<?= (' . $this->token('@@lightmode.button_bg') . ') ?>';
        $button_border = '<?= (' . $this->token('@@lightmode.button_border') . ') ?>';
        $button_text = '<?= (' . $this->token('@@lightmode.button_text') . ') ?>';
        $href = (preg_match('/\{\{(.+?)\}\}/',$attrib['href']?:'')?
                    $this->token($attrib['href']):
                    Base::instance()->stringify($attrib['href']));

        $out = '<div style="padding: 0 20px 20px;">';
        $out .= '<table align="center" role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin: auto;">';
        $out .= '<tr>';
        $out .= '<td class="button-td button-td-primary" style="border-radius: 4px; background:' . $button_bg . ';">';
        $out .= '<a class="button-a button-a-primary" href="' . $href . '" style="background: ' . $button_bg . '; border: 1px solid ' . $button_border . '; font-family: sans-serif; font-size: 15px; line-height: 15px; text-decoration: none; padding: 13px 17px; color: ' . $button_text . '; display: block; border-radius: 4px;">';
        $out .= $this->build($node);
        $out .= '</a></td>';
        $out .= '</tr>';
        $out .= '</table>';         
        $out .= '</div>';

        return $out;
    }

    /**
     * Sets a value in the return values array.
     * 
     * @param string $path the ArrayWrapper path to the value to
     * set
     * @param mixed $val the value to set
     * @return void
     */
    protected function setReturnValue(string $path, $val) {
        return $this->returnValues->set($path, $val);
    }

    /**
     * Returns all return values
     * 
     * @return array an array of return values
     */
    public function getReturnValues(): array {
        return $this->returnValues->toArray();
    }

    /**
     * Returns a value from the return values.
     * 
     * @param string $path the ArrayWrapper path to the value to
     * return
     * @return mixed
     */
    public function getReturnValue(string $path) {
        return $this->returnValues->get($path);
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
     * Filter to encode values to be included in Javascript.
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
    public function js(mixed $data = null): string {
        /* Note that all strings in $data have been escaped by F3. This
           means we have to leave ampersands intact so that they can be
           unescaped by the raw filter
         */
        $json_flags = JSON_HEX_TAG | JSON_HEX_APOS /*| JSON_HEX_AMP*/ | JSON_HEX_QUOT | JSON_THROW_ON_ERROR;
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

    public function markdown(string $md) {
        $parsedown = new \Parsedown();
        return $parsedown->text($md);
    }

    public function html_to_text(string $html, int $wordwrap = 70): string {
        return wordwrap(strip_tags(preg_replace('{<(head|style)\b.*?</\1>}is', '', $html)), $wordwrap);
    }
}

?>