<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2024
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

namespace SimpleID\Util\Events;

use SimpleID\Util\UI\AttachmentManagerInterface;
use SimpleID\Util\UI\UIBuilder;
use SimpleID\Util\UI\UIBuilderInterface;

/**
 * A generic event used to build user interfaces.
 * 
 * This event is created along with a UIBuilder. The methods from the
 * UIBuilderInterface are delegated to the attached UIBuilder.
 * 
 * @see SimpleID\Util\UI\UIBuilder
 */
class UIBuildEvent extends BaseEvent implements \GenericEventInterface, UIBuilderInterface {
    use GenericEventTrait;

    /** @var \SimpleID\Util\UI\UIBuilder */
    protected $builder;

    /**
     * Creates a UI build event
     * 
     * @param string $eventName the name of the event, or the name
     */
    public function __construct($eventName = null) {
        $this->setEventName($eventName);
        $this->builder = new UIBuilder();
    }

    /**
     * Returns the UIBuilder for this event
     * 
     * @return \SimpleID\Util\UI\UIBuilder
     */
    public function getUIBuilder() {
        return $this->builder;
    }

    /**
     * {@inheritdoc}
     */
    public function addBlock(string $id, string $content, int $weight = 0, array $additional = []): UIBuildEvent {
        $this->builder->addBlock($id, $content, $weight, $additional);
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function merge(UIBuilderInterface $builder) {
        return $this->builder->merge($builder);
    }

    /**
     * {@inheritdoc}
     */
    public function getBlocks(): array {
        return $this->builder->getBlocks();
    }

    /**
     * {@inheritdoc}
     */
    public function getBlockData(): array {
        return $this->builder->getBlockData();
    }

    /**
     * {@inheritdoc}
     */
    public function addAttachment(string $attachment_type, array $data): AttachmentManagerInterface {
        return $this->builder->addAttachment($attachment_type, $data);
    }

    /**
     * {@inheritdoc}
     */
    public function getAttachments(): array {
        return $this->builder->getAttachments();
    }

    /**
     * {@inheritdoc}
     */
    public function getAttachmentTypes(): array {
        return $this->builder->getAttachmentTypes();
    }

    /**
     * {@inheritdoc}
     */
    public function getAttachmentsByType(string $attachment_type) {
        return $this->builder->getAttachmentsByType($attachment_type);
    }

    /**
     * {@inheritdoc}
     */
    public function reset() {
        $this->builder->reset();
    }
}

?>