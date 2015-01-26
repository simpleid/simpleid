<?php

namespace SimpleID\API;

/**
 * Generic routing hooks
 */
abstract class IndexHooks {
    /**
     * Processes a request to the root route (i.e. <code>/</code>).
     *
     * If the hook is able to process the request, it should return
     * true after process.  If the hook does not recognise the request,
     * it should return null.
     *
     * @param array $request the request
     * @return true if the hook has processed the request
     */
    abstract function indexHook($request);
}

?>
