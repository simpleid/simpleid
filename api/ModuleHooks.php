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

    abstract function upgradeListHook();
}