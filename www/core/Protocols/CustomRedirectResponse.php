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
 */

namespace SimpleID\Protocols;

use \Base;
use SimpleID\Util\UI\Template;

/**
 * A class representing a response redirecting to a custom URL scheme,
 * typically used by native apps.
 * 
 * This response is rendered with an HTML page to provide instructions
 * in relation to a browser prompt.
 */
class CustomRedirectResponse {
    /** @var string $url */
    protected $url;

    /**
     * Creates a custom redirect response.
     *
     * @param string $url the redirect rul
     */
    public function __construct($url) {
        $this->url = $url;
    }

    /**
     * Renders the response.
     *
     * @return void
     */
    public function render() {
        $f3 = Base::instance();
        $tpl = Template::instance();

        $f3->set('page_class', 'is-dialog-page is-loading');
        $f3->set('title', $f3->get('intl.common.launching_native_app'));
        $f3->set('layout', 'redirect_native.html');
        $f3->set('url', $this->url);

        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }
}

?>