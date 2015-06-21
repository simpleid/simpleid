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
 */

namespace SimpleID\Util;

use \Base;
use \Prefab;
use SimpleI18N\SimpleI18N;

/**
 * The locale manager.
 *
 * It is also a wrapper for SimpleI18N.
 */
class LocaleManager extends Prefab {
    const DEFAULT_DOMAIN = SimpleI18N::DEFAULT_DOMAIN;

    private $i18n;

    public function __construct() {
        $f3 = Base::instance();
        $config = $f3->get('config');

        $this->i18n = new SimpleI18N();
        $this->i18n->addDomain(SimpleI18N::DEFAULT_DOMAIN, 'locale');
        $this->i18n->setLocale($config['locale']);
    }

    public function __call($method, $args) {
        if (method_exists($this->i18n, $method)) {
            $raw = false;
            $raw_method = $method;
            $variables = array_pop($args);
        } elseif ((substr($method, -4) == '_raw') && method_exists($this->i18n, substr($method, 0, -4))) {
            $raw = false;
            $raw_method = substr($method, 0, -4);
        } else {
            return null;
        }

        $translated = call_user_func_array(array($this->i18n, $raw_method), $args);

        if ($raw) return $translated;

        return $this->expand($translated, $variables);
    }

    /**
     * Expands a string.
     *
     * @param string $string the string to expand
     * @param array $variables an array of replacements variables to be made.
     * Prefix the variable with a @ to make the replacement HTML safe,
     * a % to make the replacement HTML safe and surround with &lt;strong&gt; tags,
     * and ! to replace as is
     * @return string the expanded string
     */
    public function expand($string, $variables) {
        $f3 = Base::instance();

        if ($variables == NULL) return $string;

        foreach ($variables as $variable => $value) {
            switch ($variable[0]) {
                case '@':
                    $variables[$variable] = $f3->clean($value);
                    break;
                case '%':
                default:
                    $variables[$variable] = '<strong>' . $f3->clean($value) . '</strong>';
                    break;
                case '!':
                // Pass-through.
            }
        }
        return strtr($string, $variables);
    }
}
 
?>
