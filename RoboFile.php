<?php

use Robo\Symfony\ConsoleIO;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Yaml\Yaml;
use SimpleID\Util\UI\Template;

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends \Robo\Tasks {
    /**
     * @option $apigen-url
     */
    public function apidocs(ConsoleIO $io, $title_template = 'SimpleID Documentation [%s]', $opts = [ 'apigen-path' => null ]) {
        // 1. Get apigen
        if (isset($opts['apigen-path'])) {
            $apigen = $opts['apigen-path'];
        } elseif (getenv('APIGEN_PATH') != null) {
            $apigen = getenv('APIGEN_PATH');
        } else {
            $io->error("apigen-path option or APIGEN_PATH variable is not defined");
            return 1;
        }

        if (!file_exists($apigen) && (filter_var($apigen, FILTER_VALIDATE_URL) !== false)) {
            $io->say('Downloading apigen.phar');

            $url = filter_var($apigen, FILTER_VALIDATE_URL);
            $data = @file_get_contents($url, false, null);
            if ($data == false) {
                $io->error("Error downloading apigen.phar");
                return 1;
            } else {
                $apigen = 'build/apigen.phar';
                file_put_contents($apigen, $data);
                chmod($apigen, 0755);
            }
        }

        // 2. Get current branch name
        //$branch_task = $this->taskExec('git rev-parse --abbrev-ref HEAD')->run();
        $branch_task = $this->taskExec('git branch --show-current')->printOutput(false)->run();
        if (!$branch_task->wasSuccessful()) {
            return $branch_task;
        }
        $branch = trim($branch_task->getMessage());

        // 3. Run apigen
        $title = sprintf($title_template, $branch);
        $this->taskExec('php')
            ->arg($apigen)
            ->option('title', $title)
            ->run();
    }

    public function update_copyright() {
        $current_year = date('Y');

        $finder = new Finder();
        $finder->in(['tests', 'www/core', 'www/upgrade', 'assets'])->name(['*.php', 'main.js'])->append(['COPYING.txt']);

        foreach($finder as $file) {
            $this->taskReplaceInFile($file)
                ->regex('/Copyright \(C\) Kelvin Mo (\d{4})-(\d{4})(\R)/m')
                ->to('Copyright (C) Kelvin Mo $1-'. $current_year . '$3')
                ->run();
            $this->taskReplaceInFile($file)
                ->regex('/Copyright \(C\) Kelvin Mo (\d{4})(\R)/m')
                ->to('Copyright (C) Kelvin Mo $1-'. $current_year . '$2')
                ->run();
        }
    }
    
    /**
     * Create frontend tests
     */
    public function make_frontend_tests() {
        $tests_dir = 'tests/frontend';
        $temp_dir = 'tests/temp';

        if (file_exists($temp_dir))
            $this->taskCleanDir($temp_dir)->run();

        $config = Yaml::parseFile($tests_dir . '/config.yml');

        foreach ($config['tests'] as $output_file => $steps) {
            $this->say($output_file);

            $f3 = \Base::instance();
            $tpl = Template::instance();

            $f3->set('TEMP', $temp_dir . '/');
            foreach ($config['globals'] as $phase) {
                $f3->mset($phase);
            }

            foreach ($steps as $step) {
                if (isset($step['template'])) {
                    $template_file = $step['template'];
                    $mime = (isset($step['mime'])) ? $step['mime'] : 'text/html';
                    $hive = (isset($step['local_variables'])) ? $step['local_variables'] : null;
                    if (isset($step['variables'])) $f3->mset($step['variables']);

                    $result = $tpl->render($template_file, $mime, $hive);
                } elseif (isset($step['resolve'])) {
                    $result = (is_string($step['resolve'])) ? $tpl->resolve($step['resolve']) : $step['resolve'];
                } elseif (isset($step['array'])) {
                    $result = [];

                    foreach ($step['array'] as $variable => $contents) {
                        $result[$variable] = (is_string($contents)) ? $tpl->resolve($contents) : $contents;
                    }
                }

                if (isset($step['set'])) {
                    $f3->set($step['set'], $result);
                } elseif (isset($step['push'])) {
                    if (is_array($f3->get($step['push']))) {
                        $f3->push($step['push'], $result);
                    } else {
                        $f3->set($step['push'], [ $result ]);
                    }
                } else {
                    $return_values = $tpl->getReturnValues();

                    $this->taskWriteToFile($tests_dir . '/' . $output_file)->text($result)->run();
                    if ($return_values) {
                        $this->taskWriteToFile($tests_dir . '/' . $output_file . '-return.yml')->text(Yaml::dump($return_values))->run();
                    }
                }
            }

            \Registry::clear(\Base::class);
            \Registry::clear(Template::class);
        }
    }

    /**
     * Watch the www/html directory for changes and run the make_frontend_tests
     * command
     */
    public function watch_frontend() {
        $this->taskWatch()
            ->monitor('www/html', function() {
                $this->make_frontend_tests();
            }
        )->run();
    }
}