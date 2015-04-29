<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-8
 *
 * Includes code Drupal OpenID module (http://drupal.org/project/openid)
 * Rowan Kerr <rowan@standardinteractive.com>
 * James Walker <james@bryght.com>
 *
 * Copyright (C) Rowan Kerr and James Walker
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
 * Default configuration settings
 *
 * @package simpleid
 * @filesource
 */

/**
 * Define a constant if it has not been defined already.
 *
 * @param $name string the name of the constant
 * @param $value mixed the value of the constant - only scalar and null values
 * are allowed
 */
function define_default($name, $value)
{
    if (!defined($name)) {
        define($name, $value);
    }
}

define_default('SIMPLEID_CLEAN_URL', false);
define_default('SIMPLEID_ALLOW_PLAINTEXT', false);
define_default('SIMPLEID_ALLOW_AUTOCOMPLETE', false);
define_default('SIMPLEID_EXTENSIONS', 'sreg');
define_default('SIMPLEID_VERIFY_RETURN_URL_USING_REALM', true);
define_default('SIMPLEID_STORE', 'filesystem');
define_default('SIMPLEID_STORE_DIR', SIMPLEID_CACHE_DIR);
define_default('SIMPLEID_LOCALE', 'en');
define_default('SIMPLEID_LOGFILE', '');
define_default('SIMPLEID_LOGLEVEL', 4);

if (function_exists('date_default_timezone_set')) {
    date_default_timezone_set(@date_default_timezone_get());
}
