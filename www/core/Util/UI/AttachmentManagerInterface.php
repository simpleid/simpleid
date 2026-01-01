<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2023-2026
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
 * Interface for managing attachments.
 * 
 * Attachments can be things such as CSS style sheets, Javascript
 * references or Javascript code.  Each attachment is associated
 * with a type.
 *
 */
interface AttachmentManagerInterface {
    /**
     * Constant specifying the attachment type for CSS stylesheets.
     * 
     * The attachment should be specified as an array with one of the following keys:
     * 
     * - inline: the css code to be emdedded
     * - src: the path to the stylesheet
     */
    const CSS_ATTACHMENT = 'css';

    /**
     * Constant specifying the attachment type for Javascript.
     * 
     * The attachment should be specified as an array with one of inline or src,
     * plus zero or more of the following keys:
     * 
     * - inline: the Javascript code to be emdedded
     * - src: the path to the script to load
     * - defer: value of the defer attribute
     * - async: value of the async attribute
     * - type: value of the type attribute
     */
    const JS_ATTACHMENT = 'js';

    /**
     * Adds an attachment.
     * 
     * @param string $attachment_type the type of attachment
     * @param array<mixed> $data the details of the attachment
     * @return AttachmentManagerInterface
     */
    public function addAttachment(string $attachment_type, array $data): AttachmentManagerInterface;

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
    public function getAttachments(): array;

    /**
     * Returns an array of attachment types currently attached.
     * 
     * @return array<string>
     */
    public function getAttachmentTypes(): array;

    /**
     * Returns the attachments of a particular type.
     * 
     * Only unique elements are returned.
     * 
     * @param string $attachment_type the attachment type
     * @return array<array<mixed>>
     */
    public function getAttachmentsByType(string $attachment_type);
}

?>