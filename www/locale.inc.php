<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2012
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
 * $Id$
 */
/**
 * Localisation support.
 *
 * @package simpleid
 * @since 0.9
 * @filesource
 */
 
include_once 'lib/gettext/gettext.inc';
 
/**
 * Initialises the localisation system.
 *
 * @param string $locale the locale to use
 */
function locale_init($locale) {
    T_setlocale(LC_MESSAGES, $locale);
    // Set the text domain as 'messages'
    $domain = 'messages';
    bindtextdomain($domain, 'locale');
    // bind_textdomain_codeset is supported only in PHP 4.2.0+
    if (function_exists('bind_textdomain_codeset')) 
        bind_textdomain_codeset($domain, 'UTF-8');
    textdomain($domain);
}

/**
 * Translates a string.
 *
 * @param string $string the string to translate
 * @param array $variables an array of replacements variables to be made after
 * a translation. Prefix the variable with a @ to make the replacement HTML safe,
 * a % to make the replacement HTML safe and surround with &lt;strong&gt; tags,
 * and ! to replace as is
 * @return string the translated string
 */
function t($string, $variables = array()) {
    $translated = gettext($string);
    
    foreach ($variables as $variable => $value) {
        switch ($variable[0]) {
            case '@':
                $variables[$variable] = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
                break;
            case '%':
            default:
                $variables[$variable] = '<strong>' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '</strong>';
                break;
            case '!':
                // Pass-through.
        }
  }
  return strtr($translated, $variables);
}
?>
