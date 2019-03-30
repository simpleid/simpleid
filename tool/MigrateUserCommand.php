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

use \Spyc;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class MigrateUserCommand extends Command {

    private $sreg_map = array(
        'nickname'=> 'nickname',
        'email'=> 'email',
        'fullname'=> 'name',
        'dob'=> 'birthday',
        'gender'=> 'gender',
        'language'=> 'locale',
        'timezone'=> 'zone_info'
    );

    protected function configure() {
        parent::configure();
        $this->setName('migrate-user')->setDescription('Converts a SimpleID 1 identity file to a SimpleID 2 user file');
        $this->addArgument('input', InputArgument::REQUIRED, 'File name of SimpleID 1 identity file');
        $this->addArgument('output', InputArgument::OPTIONAL, 'Output file name, or STDOUT if missing');
    }

    public function execute(InputInterface $input, OutputInterface $output) {
        $stderr = ($output instanceof ConsoleOutputInterface) ? $output->getErrorOutput() : $output;

        $old = parse_ini_file($input->getArgument('input'), true);
        $user = array();

        // 1. Main section
        if (isset($old['identity'])) {
            if (!isset($user['openid'])) $user['openid'] = array();
            $user['openid']['identity'] = $old['identity'];
        }

        if (isset($old['pass'])) {
            $hash_function_salt = explode(':', $old['pass'], 3);
    
            $hash = $hash_function_salt[0];
            $function = (isset($hash_function_salt[1])) ? $hash_function_salt[1] : 'md5';

            if ($function == 'pbkdf2') {
                list ($algo, $iterations, $salt) = explode(':', $hash_function_salt[2]);
                $length = (function_exists('hash')) ? strlen(hash($algo, '')) : 0;

                if ($iterations < PasswordCommand::MIN_ITERATIONS) {
                    $stderr->writeln('<error>Warning: PBKDF2 iterations too low.</error>');
                }

                if (!isset($user['password'])) $user['password'] = array();
                $user['password']['password'] = PasswordCommand::encode_hash(pack("H*" , $hash), $salt, $algo, $iterations, $length);
            } else {
                $stderr->writeln('<error>Password not converted as it no longer complies with SimpleID 2 requirements.</error>');
                $stderr->writeln('<error>Use simpleid-tool passwd to encrypt a new password.</error>');
                $stderr->writeln('<error>See http://simpleid.org/docs/2/migrating/#password for details</error>');
                $user['password']['password'] = '[ENCODE YOUR NEW PASSWORD HERE]';
            }
        }

        if (isset($old['administrator'])) {
            $user['administrator'] = $old['administrator'];
        }

        // 2. cert
        if (isset($old['certauth'])) {
            if (!isset($user['cert'])) $user['cert'] = array();
            $user['cert']['certs'] = $old['certauth']['cert'];
        }

        // 3. sreg
        if (isset($old['sreg'])) {
            if (!isset($user['userinfo'])) $user['userinfo'] = array();

            foreach($old['sreg'] as $key => $value) {
                switch ($key) {
                    case 'postcode':
                        if (!isset($user['userinfo']['address'])) $user['userinfo']['address'] = array();
                        $user['userinfo']['address']['postal_code'] = $value;
                        break;
                    case 'country':
                        if (!isset($user['userinfo']['address'])) $user['userinfo']['address'] = array();
                        $user['userinfo']['address']['country'] = $value;
                        break;
                    case 'gender':
                        if ($value == 'M') $value = 'male';
                        if ($value == 'F') $value = 'female';
                        // follow through
                    default:
                        $user['userinfo'][$this->sreg_map[$key]] = $value;
                }
            }
        }

        // 4. ax
        if (isset($old['ax'])) {
            if (!isset($user['openid'])) $user['openid'] = array();
            $user['openid']['ax'] = $old['ax'];
        }

        // 5. Userinfo
        if (isset($old['user_info'])) {
            if (!isset($user['userinfo'])) $user['userinfo'] = array();
            $user['userinfo'] = array_replace_recursive($user['userinfo'], $old['user_info']);
        }

        // 4. Results.
        $results = <<<_END_HEADER_
#
# ** Generated by SimpleIDTool **
#
# ** Review this file against example.user.yml.dist and make additional manual
# changes **
#

_END_HEADER_;

        $results .= Spyc::YAMLDump($user, 4, false, true);

        if ($input->getArgument('output')) {
            file_put_contents($input->getArgument('output', $results));
        } else {
            $output->writeln($results);
        }
    }
}

?>
