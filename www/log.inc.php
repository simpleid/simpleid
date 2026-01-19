<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-9
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
 * $Id$
 */

/**
 * Functions for logging.
 *
 * @package simpleid
 * @filesource
 */

/** Log level */
define('SIMPLEID_LOG_DEBUG', 5);
/** Log level */
define('SIMPLEID_LOG_INFO', 4);
/** Log level */
define('SIMPLEID_LOG_NOTICE', 3);
/** Log level */
define('SIMPLEID_LOG_WARN', 2);
/** Log level */
define('SIMPLEID_LOG_ERROR', 1);
/** Log level */
define('SIMPLEID_LOG_FATAL', 0);

/**
 * This variable holds the pointer to the currently opened log file.  If the
 * log file is not open, this variable is NULL.
 *
 * @global resource $log
 */
$log = NULL;


/**
 * Opens the log file.
 *
 * This function opens a pointed to the log file for later usage.
 *
 * @return bool true if the log file is opened successfully.
 */
function log_open() {
    global $log;
    if (!defined('SIMPLEID_LOGFILE') || (SIMPLEID_LOGFILE == '')) return;
    $log = fopen(SIMPLEID_LOGFILE, 'a');
    
    if ($log === false) {
        $log = NULL;
        return false;
    } else {
        return true;
    }
}

/**
 * Closes the log file, if it is open.
 */
function log_close() {
    if ($log != NULL) {
        fflush($log);
        fclose($log);
        $log = NULL;
    }
}

/**
 * Logs a DEBUG message.
 *
 * @param string $message the message to log
 * @see _log_write()
 */
function log_debug($message) {
    _log_write($message, SIMPLEID_LOG_DEBUG);
}

/**
 * Logs an INFO message.
 *
 * @param string $message the message to log
 * @see _log_write()
 */
function log_info($message) {
    _log_write($message, SIMPLEID_LOG_INFO);
}

/**
 * Logs a NOTICE message.
 *
 * @param string $message the message to log
 * @see _log_write()
 */
function log_notice($message) {
    _log_write($message, SIMPLEID_LOG_NOTICE);
}

/**
 * Logs a WARN message.
 *
 * @param string $message the message to log
 * @see _log_write()
 */
function log_warn($message) {
    _log_write($message, SIMPLEID_LOG_WARN);
}

/**
 * Logs a ERROR message.
 *
 * @param string $message the message to log
 * @see _log_write()
 */
function log_error($message) {
    _log_write($message, SIMPLEID_LOG_ERROR);
}

/**
 * Logs a FATAL message.
 *
 * @param string $message the message to log
 * @see _log_write()
 */
function log_fatal($message) {
    _log_write($message, SIMPLEID_LOG_FATAL);
}

/**
 * Converts an array into a string for logging purposes.
 *
 * @param array $array the array the convert
 * @param array $keys an array of keys to include in the converted string.  Set
 * to false if all the keys in the array should be included
 * @return string the converted string.
 */
function log_array($array, $keys = false) {
    $output = array();
    
    if ($keys == false) $keys = array_keys($array);
    
    foreach ($keys as $key) {
        $output[] = $key . ": " . $array[$key];
    }
    
    return implode('; ', $output);
}

/**
 * Logs a message
 *
 * @param string $message the message to log
 * @param int $level the log level
 * @return bool true if the log has been written successfully
 */
function _log_write($message, $level = false) {
    global $log;
    static $levels;
    
    if (!$levels) {
        $levels = array(
            SIMPLEID_LOG_DEBUG => 'DEBUG',
            SIMPLEID_LOG_INFO => 'INFO',
            SIMPLEID_LOG_NOTICE => 'NOTICE',
            SIMPLEID_LOG_WARN => 'WARN',
            SIMPLEID_LOG_ERROR => 'ERROR',
            SIMPLEID_LOG_FATAL => 'FATAL'
        );
    }
    
    /* If a priority hasn't been specified, use the default value. */
    if ($level === false) {
        $level = SIMPLEID_LOG_INFO;
    }

    /* Abort early if the priority is above the maximum logging level. */
    if ($level > SIMPLEID_LOGLEVEL) {
        return false;
    }

    /* If the log file isn't already open, open it now. */
    if (($log == NULL) && !log_open()) {
        return false;
    }

    /* Build the string containing the complete log line. */
    $line = sprintf('%1$s %2$s [%3$s] %4$s', (new DateTimeImmutable())->format(SIMPLEID_DATE_TIME_FORMAT), session_id(), $levels[$level], $message) . "\n";

    /* Write the log line to the log file. */
    $success = (fwrite($log, $line) !== false);

    return $success;
}

?>
