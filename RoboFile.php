<?php

use Gettext\Scanner\PhpScanner;
use Gettext\Generator\PoGenerator;
use Gettext\Translations;
use Symfony\Component\Finder\Finder;

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends \Robo\Tasks {
    public function xgettext() {
        $domain = 'messages';

        $finder = new Finder();
        $finder->in('www')->name('*.php');

        $translations[] = Translations::create($domain);

        $scanner = new PhpScanner(...$translations);
        $scanner->setDefaultDomain($domain);

        $scanner->setFunctions(['t' => 'gettext']);

        foreach ($finder as $file) {
            $scanner->scanFile($file);
        }

        $generator = new PoGenerator();

        foreach ($scanner->getTranslations() as $domain => $translations) {
            $destFile = 'www/locale/messages.pot';

            $translations->getHeaders()->set('Project-Id-Version', 'PACKAGE VERSION');
            $translations->getHeaders()->set('Report-Msgid-Bugs-To', '');
            $translations->getHeaders()->set('POT-Creation-Date', date('c'));
            $translations->getHeaders()->set('PO-Revision-Date', 'YEAR-MO-DA HO:MI+ZONE');
            $translations->getHeaders()->set('Last-Translator', 'FULL NAME <EMAIL@ADDRESS>');
            $translations->getHeaders()->set('Language-Team', 'LANGUAGE <LL@li.org>');
            $translations->getHeaders()->set('MIME-Version', '1.0');
            $translations->getHeaders()->set('Content-Type', 'text/plain; charset=UTF-8');
            $translations->getHeaders()->set('Content-Transfer-Encoding', '8bit');

            $generator->generateFile($translations, $destFile);
        }
    }

    public function build() {
        $ref = getenv('GITHUB_REF_NAME');
        if ($ref === false) {
            $version = 'master';
        } else {
            $version = str_replace('release-', '', $ref);
        }

        $dist_file = 'simpleid-' . $version . '.tar.gz';
        
        // 1. Set up robo collections and create temp directory
        $main_collection = $this->collectionBuilder();
        $prepare_collection = $this->collectionBuilder();
        $temp = $main_collection->tmpDir();
        $working = $main_collection->workDir("dist");

        // 3. Prepare step
        // (a) Copy files to temp directory
        $prepare_collection->taskMirrorDir([
            '.' => "$temp/simpleid"
        ]);

        // (b) remove unnecessary directories and files
        $prepare_collection->taskDeleteDir([
            "$temp/simpleid/.git",
            "$temp/simpleid/.github",
            "$temp/simpleid/.sourceforge",
            "$temp/simpleid/dist",
            "$temp/simpleid/vendor",
            "$temp/simpleid/www/vendor",
            "$temp/simpleid/www/test",
            "$temp/simpleid/www/test-suite"
        ]);

        $prepare_collection->taskFileSystemStack()->remove([
            "$temp/simpleid/www/.htaccess",
            "$temp/simpleid/www/config.inc",
            "$temp/simpleid/www/config.php",
            "$temp/simpleid/www/composer.lock",
            "$temp/simpleid/composer.lock"
        ]);

        // (c) run
        $result = $prepare_collection->run();
        if (!$result->wasSuccessful()) {
            return $result;
        }

        // 4. Replace variables
        $finder = new Finder();
        $finder->in("$temp/simpleid/www")->name('*.php')->name('*.dist');
        foreach($finder as $file) {
            $main_collection->taskReplaceInFile($file)
                ->from(['@@BUILD_VERSION@@', '@@IDENTITIES_DIR@@', '@@CACHE_DIR@@', '@@STORE_DIR@@'])
                ->to([$version, '../identities', '../cache', '../store']);
        }

        // 5. Create the release files
        $main_collection->taskFileSystemStack()->mkdir("$working/$version")->copy('.sourceforge/frs/README.md', "$working/$version/README.md");
        $main_collection->taskPack("$working/$version/$dist_file")->addDir('simpleid/', "$temp/simpleid");
        $main_collection->taskWriteToFile('version.txt')->line($version);

        // 6. Run everything
        return $main_collection->run();
    }
}