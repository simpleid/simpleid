<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2022
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

namespace SimpleID\Protocols\WebFinger;

use Psr\Log\LogLevel;
use SimpleID\Module;
use SimpleID\Store\StoreManager;
use SimpleID\Util\RateLimiter;

/**
 * A module implementing the WebFinger protocol for accessing user
 * information.
 *
 * @see http://tools.ietf.org/html/rfc7033
 * @since 2.0
 */
class WebFingerModule extends Module {
    static function init($f3) {
        $f3->route('GET|HEAD /.well-known/webfinger', 'SimpleID\Protocols\WebFinger\WebFingerModule->start');
    }

    function start() {
        $config = $this->f3->get('config');
        $limiter = new RateLimiter('webfinger');

        if (!$limiter->throttle()) {
            header('Retry-After: ' . $limiter->getInterval());
            // We never display a log for rate limit errors
            $this->f3->status(429);
            $this->fatalError($this->f3->get('intl.common.ratelimit_error'));
        }

        $this->logger->log(LogLevel::INFO, 'SimpleID\Protocols\WebFinger->start');
    
        if (!$this->f3->exists('GET.resource') || ($this->f3->get('GET.resource') == '')) {
            $this->logger->log(LogLevel::NOTICE, 'resource parameter missing or empty');
            $this->f3->status(400);
            $this->fatalError($this->f3->get('intl.core.webfinger.missing_resource'));
            return;
        }

        $resource = $this->f3->get('GET.resource');
        $this->logger->log(LogLevel::INFO, 'Requested resource URI: ' . $resource);
    
        $jrd = $this->getJRD($resource);
    
        if ($jrd == NULL) {
            $limiter->penalize();  // Stop $remote_addr from querying again
            $this->f3->status(404);
            $this->fatalError($this->f3->get('intl.common.not_found'));
            return;
        }
    
        $jrd = $this->fixJRDAliases($jrd, $resource);
    
        if (isset($_GET['rel'])) $jrd = $this->filterJRDRels($jrd, $_GET['rel']);

        header('Content-Type: application/jrd+json');
        header('Content-Disposition: inline; filename=webfinger.json');
        header('Access-Control-Allow-Origin: ' . $config['webfinger_access_control_allow_origin']);

        if ($this->f3->get('VERB') == 'HEAD') return;

        print json_encode($jrd);
    }

    /**
     * Creates a JRD document based on a SimpleID user.
     *
     * The JRD document created is very simple - it merely points to the
     * SimpleID installation as the OpenID connect provider.
     *
     * @param array $resource the resource identifier
     * @return array the JRD document
     */
    protected function getJRD($resource) {
        $store = StoreManager::instance();

        $criteria = $this->getResourceCriteria($resource);
        if ($criteria == null) return null;

        foreach ($criteria as $criterion => $value) {
            $user = $store->findUser($criterion, $value);
            if ($user != null) break;
        }
        if ($user == null) return null;

        $jrd = [
            'subject' => $user['identity'],
            'links' => [
                [
                    'rel' => 'http://specs.openid.net/auth/2.0/provider',
                    'href' => rtrim($this->f3->get('config.canonical_base_path'), '/')
                ],
                [
                    'rel' => 'http://openid.net/specs/connect/1.0/issuer',
                    'href' => rtrim($this->f3->get('config.canonical_base_path'), '/')
                ]
            ]
        ];
        
        if (isset($user['aliases'])) {
            if (is_array($user['aliases'])) {
                $jrd['aliases'] = $user['aliases'];
            } else {
                $jrd['aliases'] = [ $user['aliases'] ];
            }
        }
        
        return $jrd;
    }

    /**
     * Obtains the criteria to search, based on a specified resource
     * identifier.
     *
     * This function works out the type of resource being requested (e.g.
     * URL or e-mail), then supplies the appropriate path(s) to search
     * for.
     * @param string $resource the resource identifier
     * @return array an array of criteria paths and their corresponding
     * values
     */
    protected function getResourceCriteria($resource) {
        $audit = \Audit::instance();

        if ($audit->url($resource)) return [ 'openid.identity' => $resource ];

        // If it begins with acct: or mailto:, strip it out
        if ((stristr($resource, 'acct:') !== false) || (stristr($resource, 'mailto:') !== false)) {
            list (, $email) = explode(':', $resource, 2);
            if ($audit->email($email)) {
                return [ 'webfinger.acct' => $email, 'userinfo.email' => $email ];
            }
        }

        return null;
    }

    /**
     * Ensures that a specified resource URI occurs in either the subject or
     * the aliases member of a JRD document.
     *
     * @param array $jrd the JRD document
     * @param string $resource the resource URI
     * @return array the fixed JRD document
     */
    protected function fixJRDAliases($jrd, $resource) {
        if (isset($jrd['subject']) && ($jrd['subject'] == $resource)) return $jrd;
        
        if (isset($jrd['aliases'])) {
            $found = FALSE;
            foreach ($jrd['aliases'] as $alias) {
                if ($alias == $resource) {
                    $found = TRUE;
                    break;
                }
                if (!$found) $jrd['aliases'][] = $resource;
            }
        } else {
            $jrd['aliases'] = [ $resource ];
        }
        return $jrd;
    }

    /**
     * Filters a JRD document for specified link relations.
     *
     * @param array $jrd the JRD document
     * @param string|array $rels a string contain a link relation, or an array containing
     * multiple link relations, to filter
     * @return array the filtered JRD document
     */
    protected function filterJRDRels($jrd, $rels) {
        if (isset($jrd['links'])) {
            if (!is_array($rels)) $rels = [ $rels ];
             
            $links = $jrd['links'];
            $filtered_links = [];
            
            foreach ($links as $link) {
                if (isset($link['rel']) && in_array($link['rel'], $rels)) {
                    $filtered_links[] = $link;
                }
            }
            
            $jrd['links'] = $filtered_links;
        }
        return $jrd;
    }
}


?>
