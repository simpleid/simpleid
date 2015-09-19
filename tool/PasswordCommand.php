<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014
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

namespace SimpleIDTool;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\Question;

/**
 * Command to encode a password
 */
class PasswordCommand extends Command {

    const MIN_ITERATIONS = 4096;
    const DEFAULT_ITERATIONS = 100000;

    protected function configure() {
        parent::configure();
        $this->setName('passwd')->setDescription('Encodes a password');
        $this->addArgument('password', InputArgument::OPTIONAL, 'Password to encode (prompt if missing)');
        $this->addOption('algorithm', 'f', InputOption::VALUE_REQUIRED, 'HMAC algorithm', 'sha256');
        $this->addOption('iterations', 'c', InputOption::VALUE_REQUIRED, 'Number of iterations', self::DEFAULT_ITERATIONS);
        $this->addOption('key-length', 'd', InputOption::VALUE_REQUIRED, 'Length of output, with 0 being the full length', 0);
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        $algo = $input->getOption('algorithm');
        if (!in_array($algo, hash_algos())) {
            $output->writeln('Invalid algorithm: ' . $algo);
            return 1;
        }

        $iterations = $input->getOption('iterations');
        if (!is_int($iterations) || ($iterations < self::MIN_ITERATIONS)) {
            $output->writeln('Number of iterations invalid or too small (at least ' . self::MIN_ITERATIONS . '): ' . $iterations);
            return 1;
        }

        $length = $input->getOption('key-length');
        if (!is_int($iterations) || ($iterations < 0)) {
            $output->writeln('Invalid key length: ' . $iterations);
            return 1;
        }

        if ($input->getArgument('password')) {
            $password = $input->getArgument('password');
        } elseif (!$input->getOption('no-interaction')) {
            $helper = $this->getHelper('question');

            $question = new Question('Password: ');
            $question->setHidden(true);
            $question->setHiddenFallback(false);
            $question->setValidator(function ($value) {
                if (trim($value) == '') {
                    throw new \Exception('The password cannot be blank');
                }

                return $value;
            });
            $password = $helper->ask($input, $output, $question);

            $question = new Question('Re-type password: ');
            $question->setHidden(true);
            $question->setHiddenFallback(false);
            $verify_password = $helper->ask($input, $output, $question);

            if ($password != $verify_password) {
                $output->writeln('<error>Passwords do not match</error>');
                return 1;
            }
        } else {
            $output->writeln('Password required');
            return 1;
        }

        $salt = $this->random_bytes(32);
        $hash = $this->hash_pbkdf2($algo, $password, $salt, $iterations, $length, true);

        $output->writeln(self::encode_hash($hash, $salt, $algo, $iterations, $length));
    }

    private function random_bytes($num_bytes) {
        $is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
        
        if ($is_windows) {
            // Windows
            if (function_exists('mcrypt_create_iv') && version_compare(PHP_VERSION, '5.3.0', '>=')) 
                return mcrypt_create_iv($num_bytes);

            if (function_exists('openssl_random_pseudo_bytes') && version_compare(PHP_VERSION, '5.3.4', '>='))
                return openssl_random_pseudo_bytes($num_bytes);
        }

        if (!$is_windows && function_exists('openssl_random_pseudo_bytes'))
            return openssl_random_pseudo_bytes($num_bytes);

        $bytes = '';
        if ($f === null) {
            if ('/dev/random' === null) {
                $f = FALSE;
            } else {
                $f = @fopen('/dev/random', "r");
            }
        }
        if ($f === FALSE) {
            $bytes = '';
            for ($i = 0; $i < $num_bytes; $i += 4) {
                $bytes .= pack('L', mt_rand());
            }
            $bytes = substr($bytes, 0, $num_bytes);
        } else {
            $bytes = fread($f, $num_bytes);
            fclose($f);
        }
        return $bytes;
    }

    private function hash_pbkdf2($algo, $password, $salt, $iterations, $length = 0, $raw_output = false) {
        if (function_exists('hash_pbkdf2')) {
            return hash_pbkdf2($algo, $password, $salt, $iterations, $length, $raw_output);
        }

        $result = '';
        $hLen = strlen(hash($algo, '', true));
        if ($length == 0) {
            $length = $hLen;
            if (!$raw_output) $length *= 2;
        }
        $l = ceil($length / $hLen);

        for ($i = 1; $i <= $l; $i++) {
            $U = hash_hmac($algo, $salt . pack('N', $i), $password, true);
            $T = $U;
            for ($j = 1; $j < $iterations; $j++) {
                $T ^= ($U = hash_hmac($algo, $U, $password, true));
            }
            $result .= $T;
        }

        return substr(($raw_output) ? $result : bin2hex($result), 0, $length);
    }

    static function encode_hash($hash, $salt, $algo, $iterations, $length = 0) {
        $params = array('f' => $algo, 'c' => $iterations);
        if ($length > 0) $params['dk'] = $length;
        return '$pbkdf2$' . http_build_query($params) . '$' . base64_encode($hash) . '$' . base64_encode($salt);
    }
}



?>
