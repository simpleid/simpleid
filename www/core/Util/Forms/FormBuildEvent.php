<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021
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

namespace SimpleID\Util\Forms;

use SimpleID\Util\Events\UIBuildEvent;

/**
 * A generic event used to build forms.
 *
 */
class FormBuildEvent extends UIBuildEvent implements FormEventInterface {

    protected $form_state = null;

    /**
     * Creates a form build event
     * 
     * @param string $eventName the name of the event, or the name
     * @param SimpleID\Util\Forms\FormState $form_state a reference to the form state array
     */
    public function __construct($eventName = null, $form_state = null) {
        parent::__construct($eventName);
        $this->form_state = $form_state;
    }

    /**
     * {@inheritdoc}
     */
    public function getFormState() {
        return $this->form_state;
    }
}

?>