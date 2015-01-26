<?php

namespace SimpleID\API;

/**
 * Preferences related hooks
 */
abstract class MyHooks {
    /**
     * Returns additional blocks to be displayed in the user's dashboard
     * (previously <code>hook_page_dashboard</code>).
     *
     * A block is coded as an array in accordance with the specifications set
     * out in <code>MyModule</code>.
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
     * (previously <code>hook_page_profile</code>).
     *
     * A block is coded as an array in accordance with the specifications set
     * out in <code>MyModule</code>.
     *
     * This hook should return an <i>array</i> of blocks, i.e. an array of
     * arrays.
     *
     * @see page_profile()
     * @return array an array of blocks to add to the user's profile page
     * @since 0.7
     */
    abstract function profileBlocksHook();
}

?>
