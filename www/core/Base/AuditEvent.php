<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2021-2023
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

namespace SimpleID\Base;

use \DateTimeImmutable;
use \ReflectionClass;
use \Base;
use \GenericEventInterface;
use Web\Geo;
use SimpleID\Store\Storable;
use SimpleID\Util\Events\BaseEvent;
use SimpleID\Util\Events\GenericEventTrait;

/**
 * An event to collect scope information.
 * 
 * Different identity protocols use the concept of *scope* to limit
 * the extent to which authorisation is provided by the user.  This
 * event is used to collect all the possible scopes that this
 * SimpleID installation can provide, as well as human-friendly
 * information on these scopes.
 * 
 * Scope information is categorised into *types*.  Generally each
 * identity protocol would have a separate type assigned.  Currently
 * the available types are:
 * 
 * - `openid` for the OpenID 1 and 2 protocols
 * - `oauth` for OAuth based protocols (including OpenID Connect)
 * 
 * Listeners should use {@link addScopeInfo()} to add scope information.
 */
class AuditEvent extends BaseEvent {

    /** @var \DateTimeImmutable */
    protected $time;

    /** @var string|null */
    protected $ip = null;

    /** @var string|null */
    protected $userAgent = null;

    /** @var array<string, string>|null */
    protected $location = null;

    /** @var Storable|null */
    protected $subject;

    /** @var Storable|null */
    protected $client;

    public function __construct(Storable $subject = null, Storable $client = null) {
        $f3 = Base::instance();
        $geo = Geo::instance();

        $this->time = new DateTimeImmutable();
        $this->ip = $f3->get('IP');
        $this->userAgent = $f3->get('AGENT');

        if (($this->ip != null) && $f3->get('config.log_location')) {
            $location = $geo->location($this->ip);
            $this->location = ($location === false) ? null : $location;
        }

        $this->subject = $subject;
        $this->client = $client;
    }

    /**
     * Returns the time the event occurred.
     * 
     * @return \DateTimeImmutable
     */
    public function getTime() {
        return $this->time;
    }

    /**
     * Returns the IP address of the user agent that triggered this event.
     * 
     * @return string|null the IP address or null if the IP address is not
     * available
     */
    public function getIP() {
        return $this->ip;
    }

    /**
     * Returns the user agent that triggered this event.
     * 
     * @return string|null the name of the user agent or null if it is not
     * available
     */
    public function getUserAgent() {
        return $this->userAgent;
    }

    /**
     * Returns the location information based on the IP address.
     * 
     * The location information is an array returned by Fat-Free Framework's
     * `\Web\Geo::location()` function.
     * 
     * @see http://fatfreeframework.com/3.8/geo#location
     * @return array<string, string>|null an array containing location information,
     * or null if the information is not available
     */
    public function getLocation() {
        return $this->location;
    }

    /**
     * Returns the subject (usually the user) affected by this event.
     * 
     * @return Storable|null the subject affected by this event
     */
    public function getSubject() {
        return $this->subject;
    }

    /**
     * Returns the client affected by this event.
     * 
     * @return Storable|null the client affected by this event
     */
    public function getClient() {
        return $this->client;
    }

    /**
     * Returns a shortened event name for audit purposes.
     * 
     * If the event implements GenericEventInterface, this is equivalent to
     * `getEventName()`.  Otherwise, it returns the name of the event class,
     * without the namespace.
     * 
     * Classes that do not use GenericEventInterface may wish to
     * override this method to return a shorter event name.
     * 
     * @return string
     */
    public function getAuditEventName(): string {
        if ($this instanceof GenericEventInterface) {
            return $this->getEventName();
        } else {
            return (new ReflectionClass($this))->getShortName();
        }
    }
}

?>