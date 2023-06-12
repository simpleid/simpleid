<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2023
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
 * Interface for building user interfaces.
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
interface UIBuilderInterface extends AttachmentManagerInterface {
    /**
     * Adds a UI block.
     * 
     * @param string $id the block ID
     * @param string $content the contents
     * @param int $weight the weight
     * @param array<string, mixed> $additional additional data
     * @return UIBuilderInterface
     */
    public function addBlock($id, $content, $weight = 0, $additional = []);

    /**
     * Merges another UI builder into this builder.
     * 
     * Blocks from the other builder are appended to this builder.
     * Attachments from the other builder are also appended, while
     * preserving the type.
     * 
     * @param UIBuilderInterface $builder the builder to merge
     * @return UIBuilderInterface
     */
    public function merge(UIBuilderInterface $builder);

    /**
     * Retrieves the blocks from the builder, ordered by the
     * weight, from lowest to highest.
     * 
     * @return array<array<mixed>>
     */
    public function getBlocks();

    /**
     * Retrieves the raw block data stored in the builder.
     * 
     * @return array<array<mixed>>
     */
    public function getBlockData();
}

?>