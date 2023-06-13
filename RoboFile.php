<?php

use Symfony\Component\Finder\Finder;
use SimpleID\Util\UI\Template;

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends \Robo\Tasks {
    public function update_copyright() {
        $current_year = date('Y');

        $finder = new Finder();
        $finder->in(['tests', 'www/core', 'www/upgrade'])->name('*.php')->append(['COPYING.txt']);

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
        $f3 = \Base::instance();
        $tpl = Template::instance();

        $config = Spyc::YAMLLoad($tests_dir . '/config.yml');

        foreach ($config['globals'] as $phase) {
            $f3->mset($phase);
        }

        foreach ($config['tests'] as $output_file => $steps) {
            $this->say($output_file);

            foreach ($steps as $step) {
                if (isset($step['template'])) {
                    $template_file = $step['template'];
                    if (isset($step['variables'])) $f3->mset($step['variables']);

                    $result = $tpl->render($template_file);
                } elseif (isset($step['resolve'])) {
                    $result = $tpl->resolve($step['resolve']);
                } elseif (isset($step['array'])) {
                    $result = [];

                    foreach ($step['array'] as $variable => $contents) {
                        $result[$variable] = $tpl->resolve($contents);
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
                    $this->taskWriteToFile($tests_dir . '/' . $output_file)->text($result)->run();
                }
            }
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