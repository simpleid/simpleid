<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2023
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
class UIBuilder {


    /** @var array<array<mixed>> */
    protected $blocks = [];

    /** @var array<string, array<mixed>> */
    protected $attachments = [];


    /**
     * Adds a UI block to the builder.
     * 
     * @param string $id the block ID
     * @param string $content the contents
     * @param int $weight the weight
     * @param array<string, mixed> $additional additional data
     * @return UIBuilder
     */
    public function addBlock($id, $content, $weight = 0, $additional = []) {
        $block = [ 'id' => $id, 'content' => $content, 'weight' => $weight ];
        $block = array_merge($block, $additional);

        $this->blocks[] = [
            '#data' => $block,
            '#weight' => $weight
        ];

        return $this;
    }

    /**
     * Adds an attachment to the builder
     * 
     * An *attachment* can be a CSS stylesheet or a Javascript file
     * 
     * @param string $attachment_type the type of attachment
     * @param mixed $data the details of the attachment
     * @return UIBuilder
     */
    public function addAttachment($attachment_type, $data) {
        if (isset($this->attachments[$attachment_type])) {
            $this->attachments[$attachment_type][] = $data;
        } else {
            $this->attachments[$attachment_type] = [ $data ];
        }

        return $this;
    }

    /**
     * Merges another UI builder into this builder.
     * 
     * Blocks from the other builder are appended to this builder.
     * Attachments from the other builder are also appended, while
     * preserving the type.
     * 
     * @param UIBuilder $builder the builder to merge
     * @return UIBuilder
     */
    public function merge(UIBuilder $builder) {
        $this->blocks = array_merge($this->blocks, $builder->blocks);
        $this->attachments = array_merge_recursive($this->attachments, $builder->attachments);
        return $this;
    }

    /**
     * Retrieves the blocks from the builder, ordered by the
     * weight, from lowest to highest.
     * 
     * @return array<array<mixed>>
     */
    public function getBlocks() {
        uasort($this->blocks, function($a, $b) { if ($a['#weight'] == $b['#weight']) { return 0; } return ($a['#weight'] < $b['#weight']) ? -1 : 1; });
        return array_map(function($a) { return $a['#data']; }, $this->blocks);
    }

    /**
     * Retrieves all the attachments.
     * 
     * This function returns an array of all attachments, with the
     * key being the attachment type, and the value an array of the
     * attachment details.
     * 
     * Note that the value array may contain duplicates.  To filter
     * for unique values, use the {@link getAttachmentsByType()} method.
     * 
     * @return array<string, array<mixed>> the attachments
     */
    public function getAttachments() {
        return $this->attachments;
    }

    /**
     * Returns an array of attachment types currently attached to the
     * builder.
     * 
     * @return array<string>
     */
    public function getAttachmentTypes() {
        return array_keys($this->attachments);
    }

    /**
     * Returns the attachments of a particular type.
     * 
     * Only unique elements are returned.
     * 
     * @param string $attachment_type the attachment type
     * @return array<array<mixed>>
     */
    public function getAttachmentsByType($attachment_type) {
        if (!isset($this->attachments[$attachment_type])) return [];
        return array_unique($this->attachments[$attachment_type]);
    }
}

?>