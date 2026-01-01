<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2026
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

namespace SimpleID\Store;

/**
 * Interface representing an item that can be stored using
 * {@link StoreManager}.
 */
interface Storable {
    /**
     * Returns the item type for this object
     *
     * @return string the item type
     */
    public function getStoreType();

    /**
     * Returns the unique item ID for this object.
     * 
     * @return string the ID for this object
     */
    public function getStoreID();

    /**
     * Sets the unique item ID for this object
     *
     * The ID should be:
     *
     * - unique for all items of this type; and
     * - able to be used as a file name.
     *
     * @param string $id the ID for this object
     * @return void
     */
    public function setStoreID($id);
}

?>