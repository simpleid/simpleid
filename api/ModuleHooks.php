<?php

namespace SimpleID\API;

/**
 * Generic hooks for SimpleID modules
 */
abstract class ModuleHooks {
    /**
     * Initialises a module.
     *
     * Use this hook to perform initialisation functions which can only be
     * done after all modules have been loaded.
     *
     * This hook is *not* invoked during the upgrade process.
     */
    abstract function initHook();

    /**
     * Returns a list of upgrade functions for this module.
     *
     * The list should be set out as an array, with the keys being the
     * version to be upgraded, and the value being another array
     * of function names to be called as part of the upgrade.
     *
     * If the current version of SimpleID is older than the version
     * the version specified in the keys, then the functions in the value
     * will be called.
     *
     * @return array a list of upgrade functions.
     */
    abstract function upgradeListHook();
}