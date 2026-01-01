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
 * 
 */

namespace SimpleID\Store;

use SimpleID\Module;

/**
 * An abstract class for data store modules.
 */
abstract class StoreModule extends Module {
    /**
     * Creates an instance of the store module.
     *
     * The default constructor registers the store module with the
     * store manager by calling {@link StoreManager::addStore()}.
     */
    public function __construct() {
        parent::__construct();
        $store_manager = StoreManager::instance();
        $store_manager->addStore($this, $this->getStores());
    }

    /**
     * Returns the stores that are implemented by this
     * module.
     *
     * @return array<string> stores that are implemented by this
     * module
     */
    abstract public function getStores();

    /**
     * Finds an item with the specified type and search criteria.
     * The search criteria is defined by the store.
     *
     * @param string $type the item type
     * @param string $criteria the criteria name
     * @param mixed $value the criteria value
     * @return string|null the item identifier or null if no item matches the
     * specified criteria
     */
    abstract public function find($type, $criteria, $value);

    /**
     * Reads an item.
     *
     * @param string $type the item type
     * @param string $id the item identifier
     * @return Storable|null the item or null if no item matches the
     * specified criteria
     */
    abstract public function read($type, $id);

    /**
     * Writes an item.
     *
     * @param string $type the item type
     * @param string $id the item identifier
     * @param Storable $value the item
     * @return void
     */
    abstract public function write($type, $id, $value);

    /**
     * Deletes an item.
     *
     * @param string $type the item type
     * @param string $id the item identifier
     * @return void
     */
    abstract public function delete($type, $id);

    /**
     * Returns whether an item exists.
     *
     * @param string $type the item type
     * @param string $id the item identifier
     * @return bool true if the item exists
     */
    abstract public function exists($type, $id);

    /**
     * Returns whether $haystack contains or equals to $needle.
     * 
     * If $haystack is a scalar, then this function returns whether $needle equals
     * $haystack.
     * 
     * If $haystack is a list (i.e. an array of sequential integer keys), this
     * function returns whether a value of $haystack contains $needle.
     * 
     * If $haystack is an associative array, this function contains whether a key
     * of $haystack contains $needle.
     * 
     * @param mixed $needle the value to find
     * @param mixed $haystack the item to search for the value
     * @param ?string $id the id to save cache information in
     * @param array<mixed, mixed> &$index cache
     */
    protected function equalsOrContainsValue($needle, $haystack, $id, &$index): bool {
        if (is_array($haystack)) {
            $elements = array_keys($haystack);
            if ($elements == range(0, count($haystack) - 1)) {
                // $haystack is a list (i.e. sequential integer keys),
                // so we test the values rather than the keys
                $elements = $haystack;
            }

            foreach ($elements as $element) {
                if ((trim($element) != '') && ($id != null)) $index[$element] = $id;
                if ($element == $needle) return true;
            }
        } else {
            if (trim($haystack) != '') {
                if ($id != null) $index[$haystack] = $id;
                if ($haystack == $needle) return true;
            }
        }
        return false;
    }
}

?>