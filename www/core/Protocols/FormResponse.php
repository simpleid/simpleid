<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2025
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
use SimpleID\Util\ArrayWrapper;
use SimpleID\Util\UI\Template;

/**
 * A class representing a response to be rendered using an HTML
 * form.
 */
class FormResponse extends ArrayWrapper {
    /**
     * Creates a form response.
     *
     * @param array<string, string> $data the initial response parameters
     */
    public function __construct($data = []) {
        parent::__construct($data);
    }

    /**
     * Renders the response as a POST request.
     *
     * @param string $url the URL to which the response is sent
     * @return void
     */
    public function render($url) {
        $f3 = Base::instance();
        $tpl = Template::instance();

        $f3->set('page_class', 'is-dialog-page is-loading');
        $f3->set('title', $f3->get('intl.common.please_wait'));
        $f3->set('layout', 'post.html');
        $f3->set('url', $url);
        $f3->set('params', $this->container);

        header('X-Frame-Options: DENY');
        print $tpl->render('page.html');
    }
}

?>