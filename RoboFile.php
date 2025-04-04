<?php

use Symfony\Component\Finder\Finder;
use Symfony\Component\Yaml\Yaml;
use SimpleID\Util\UI\Template;

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends \Robo\Tasks {
    public function apigen($title = null) {
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