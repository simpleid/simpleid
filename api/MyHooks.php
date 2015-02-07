<?php

namespace SimpleID\API;

/**
 * Preferences related hooks
 */
abstract class MyHooks {
    /**
     * Returns additional blocks to be displayed in the user's dashboard
     * (previously `hook_page_dashboard`).
     *
     * A block is coded as an array in accordance with the specifications set
     * out in `MyModule`.
     *
     * This hook should return an <i>array</i> of blocks, i.e. an array of
     * arrays.
     *
     * @return array an array of blocks to add to the user's dashboard
     * @since 0.7
     */
    abstract function dashboardBlocksHook();

    /**
     * Returns additional blocks to be displayed in the user's profile page
     * (previously `hook_page_profile`).
     *
     * A block is coded as an array in accordance with the specifications set
     * out in `MyModule`.
     *
     * This hook should return an <i>array</i> of blocks, i.e. an array of
     * arrays.
     *
     * @return array an array of blocks to add to the user's profile page
     * @since 0.7
     */
    abstract function profileBlocksHook();

    /**
     * Returns an array of navigation menu items.
     *
     * @return array an array of navigation menu items
     */
    abstract function navHook();
}

?>
