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

namespace SimpleID\Util\UI;

/**
 * A builder to build user interfaces.
 * 
 * User interfaces built by adding "blocks" using the {@link addBlock()}
 * method.  A block is essentially a piece of HTML code that can be
 * inserted in a particular order.
 * 
 * In addition to blocks, attachments can also be added.  Attachments
 * can be things such as CSS style sheets, Javascript references or
 * Javascript code.  Each attachment is associated with a type.
 *
 */
class UIBuilder implements UIBuilderInterface {
    use AttachmentManagerTrait;

    /** @var array<array<mixed>> */
    protected $blocks = [];

    /**
     * {@inheritdoc}
     */
    public function addBlock(string $id, string $content, int $weight = 0, array $additional = []): UIBuilder {
        $block = [ 'id' => $id, 'content' => $content, 'weight' => $weight ];
        $block = array_merge($block, $additional);

        $this->blocks[] = [
            '#data' => $block,
            '#weight' => $weight
        ];

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function merge(UIBuilderInterface $builder) {
        $this->blocks = array_merge($this->blocks, $builder->getBlockData());
        $this->mergeAttachments($builder);
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getBlocks(): array {
        uasort($this->blocks, function($a, $b) { if ($a['#weight'] == $b['#weight']) { return 0; } return ($a['#weight'] < $b['#weight']) ? -1 : 1; });
        return array_map(function($a) { return $a['#data']; }, $this->blocks);
    }

    /**
     * {@inheritdoc}
     */
    public function getBlockData(): array {
        return $this->blocks;
    }

    /**
     * {@inheritdoc}
     */
    public function reset() {
        $this->blocks = [];
        $this->resetAttachments();
    }
}

?>