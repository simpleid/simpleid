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

use Psr\EventDispatcher\StoppableEventInterface;
use SimpleID\Util\Events\GenericEventTrait;
use SimpleID\Util\Events\StoppableEventTrait;

/**
 * A generic event used to process a submitted form.  Processing in this
 * context includes validating whether the data submitted in a form is valid.
 * 
 * If a validation error is encountered, call {@link setInvalid()}.  Validation
 * messages can be added using {@link addMessage()}.
 * 
 * This event implements `StoppableEventInterface`, which stops further
 * processing of the form.  The documentation of the specific event should
 * specify when processing should be stopped - an invalid validation
 * result is not sufficient reason for further processing to be stopped.
 *
 */
class FormSubmitEvent implements \GenericEventInterface, StoppableEventInterface, FormEventInterface {
    use GenericEventTrait;
    use StoppableEventTrait;

    protected $form_state;
    protected $is_valid = true;
    protected $messages = [];


    /**
     * Creates a form submission event.
     * 
     * @param SimpleID\Util\Forms\FormState $form_state a reference to the form state array
     * @param string $eventName the name of the event, or the name
     */
    public function __construct($form_state, $eventName = null) {
        $this->setEventName($eventName);
        $this->form_state = $form_state;
    }

    /**
     * {@inheritdoc}
     */
    public function getFormState() {
        return $this->form_state;
    }

    /**
     * Adds a validation error message
     * 
     * @param string $message the error message
     */
    public function addMessage($message) {
        $this->messages[] = $message;
    }

    /**
     * Returns a list of error messages
     * 
     * @return array the error messages
     */
    public function getMessages() {
        return $this->messages;
    }

    /**
     * Sets the form validation result as invalid.
     */
    public function setInvalid() {
        $this->is_valid = false;
    }

    /**
     * Returns whether the form has been validated.
     * 
     * @return bool true if the form is valid
     */
    public function isValid() {
        return $this->is_valid;
    }
}

?>