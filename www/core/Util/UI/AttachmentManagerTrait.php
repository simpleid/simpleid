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
 * A trait to implement AttachmentManagerInterface.
 * 
 * @see AttachmentManagerInterface
 *
 */
trait AttachmentManagerTrait {
    /** @var array<string, array<mixed>> */
    protected $attachments;

    /**
     * Adds an attachment.
     * 
     * @param string $attachment_type the type of attachment
     * @param array<mixed> $data the details of the attachment
     * @return AttachmentManagerInterface
     */
    public function addAttachment(string $attachment_type, array $data): AttachmentManagerInterface {
        if (isset($this->attachments[$attachment_type])) {
            $this->attachments[$attachment_type][] = $data;
        } else {
            $this->attachments[$attachment_type] = [ $data ];
        }

        return $this;
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
    public function getAttachments(): array {
        return $this->attachments;
    }

    /**
     * Returns an array of attachment types currently attached to the
     * builder.
     * 
     * @return array<string>
     */
    public function getAttachmentTypes(): array {
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
    public function getAttachmentsByType(string $attachment_type): array {
        if (!isset($this->attachments[$attachment_type])) return [];
        return array_unique($this->attachments[$attachment_type]);
    }

    /**
     * Merges another attachment manager.
     * 
     * @param AttachmentManagerInterface $manager the attachment manager to merge
     * @return void
     */
    public function mergeAttachments(AttachmentManagerInterface $manager) {
        $this->attachments = array_merge_recursive($this->attachments, $manager->getAttachments());
    }
}

?>