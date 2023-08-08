<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2023
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

namespace SimpleID\Util;

use \Log;
use \Psr\Log\LoggerInterface;
use \Psr\Log\LogLevel;
use \Psr\Log\LoggerTrait;

/**
 * The default SimpleID logger.
 *
 * This logger extends the logger included in the PSR-3 framework
 * by implementing the PSR-3 specification.  In addition, it retains the
 * same log file format as per SimpleID 1.
 *
 * You can replace this logger with any PSR-3 compliant logger.
 * 
 */
class DefaultLogger extends Log implements LoggerInterface {

    use LoggerTrait;

    /** @var string */
    protected $log_level;

    /** @var array<string, int> */
    protected static $log_levels = [
        LogLevel::EMERGENCY => 0,
        LogLevel::ALERT => 1,
        LogLevel::CRITICAL => 2,
        LogLevel::ERROR => 3,
        LogLevel::WARNING => 4,
        LogLevel::NOTICE => 5,
        LogLevel::INFO => 6,
        LogLevel::DEBUG => 7,
    ];

    /**
     * Creates a logger based on the Fat-Framework.  The log file
     * will be placed under the directory specified by the Fat-Free
     * LOGS variable
     *
     * @param array<string, mixed> $config the SimpleID configuration
     */
    function __construct($config) {
        parent::__construct(basename($config['log_file']));

        $this->log_level = $config['log_level'];
    }

    /**
     * Logs a message with an INFO log level.  Direct resplacement
     * of the parent log function
     *
     * @param string $text the message to log
     * @param string $format ignored.
     */
    function write($text, $format = 'r') {
        $this->log(LogLevel::INFO, $text);
        return '';
    }

    /**
     * Logs a message
     *
     * @param string $level the log level
     * @param string $message the message to log
     * @param array<string, mixed> $context the context
     */
    function log($level, $message, array $context = []) {
        $fw = \Base::instance();
        $config = $fw->get('config');
        $time = new \DateTimeImmutable();

        if (self::$log_levels[$level] > self::$log_levels[$config['log_level']]) return;

        if (count($context) > 0) $message .= ' ' . json_encode($context);

        $line = sprintf('%1$s %2$s [%3$s] %4$s', $time->format($config['date_time_format']), session_id(), $level, $message) . "\n";

        $fw->write($this->file, $line, true);
    }
}

?>
