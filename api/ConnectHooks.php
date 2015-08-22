<?php

namespace SimpleID\API;

/**
 * OpenID Connect related hooks
 */
abstract class ConnectHooks {
    /**
     * Build a set of claims to be included in an ID token or UserInfo response
     *
     * @param SimpleID\Models\User $user the user about which the ID
     * token is created
     * @param SimpleID\Models\Client $client the client to which the
     * ID token will be sent
     * @param string $context the context, either `id_token` or `userinfo`
     * @param array $scopes the scope
     * @param array $claims_requested the claims requested in the request object,
     * or null if the request object is not present
     * @return array an array of claims
     */
    abstract function connectbuildClaimsHook($user, $client, $context, $scopes, $claims_requested = NULL);
}

?>
