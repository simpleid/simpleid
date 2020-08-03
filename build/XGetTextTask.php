<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Gettext\Scanner\PhpScanner;
use Gettext\Generator\PoGenerator;
use Gettext\Translations;

class XGetTextTask extends MatchingTask {
    private $destinationDir;
    private $domains = [ 'messages' ];
    private $charset = 'UTF-8';
    private $filesets = [];

    public function setDestDir(PhingFile $destinationDir) {
        $this->destinationDir = $destinationDir;
    }

    public function setDomains($domains) {
        $this->domains = preg_split('/\s+/', $domains);
    }

    public function setCharset($charset) {
        $this->charset = $charset;
    }

    public function createFileSet() {
        $this->fileset = new IterableFileSet();
        $this->filesets[] = $this->fileset;

        return $this->fileset;
    }

    public function main() {
        $this->checkPreconditions();

        try {
            $this->log('Scanning for strings', Project::MSG_INFO);

            $translations = [];
            foreach ($this->domains as $domain) {
                $translations[] = Translations::create($domain);
            }
            $scanner = new PhpScanner(...$translations);
            $scanner->setDefaultDomain($this->domains[0]);

            $scanner->setFunctions(['t' => 'gettext']);

            foreach ($this->filesets as $fileset) {
                foreach ($fileset as $file) {
                    $scanner->scanFile($file);
                }
            }

            $generator = new PoGenerator();

            foreach ($scanner->getTranslations() as $domain => $translations) {
                $destFile = $this->destinationDir . '/' . $domain . '.pot';
                $this->log('Writing ' . $destFile, Project::MSG_INFO);

                $translations->getHeaders()->set('Project-Id-Version', 'PACKAGE VERSION');
                $translations->getHeaders()->set('Report-Msgid-Bugs-To', '');
                $translations->getHeaders()->set('POT-Creation-Date', date('c'));
                $translations->getHeaders()->set('PO-Revision-Date', 'YEAR-MO-DA HO:MI+ZONE');
                $translations->getHeaders()->set('Last-Translator', 'FULL NAME <EMAIL@ADDRESS>');
                $translations->getHeaders()->set('Language-Team', 'LANGUAGE <LL@li.org>');
                $translations->getHeaders()->set('MIME-Version', '1.0');
                $translations->getHeaders()->set('Content-Type', 'text/plain; charset=' . $this->charset);
                $translations->getHeaders()->set('Content-Transfer-Encoding', '8bit');

                $generator->generateFile($translations, $destFile);
            }
        } catch (Exception $e) {
            throw new BuildException(
                'Problem creating package: ' . $e->getMessage(),
                $e,
                $this->getLocation()
            );
        }
    }

    private function checkPreconditions() {
        if (null === $this->destinationDir) {
            throw new BuildException("destdir attribute must be set!", $this->getLocation());
        }

        if ($this->destinationDir->exists() && !$this->destinationDir->isDirectory()) {
            throw new BuildException("destdir is not a directory!", $this->getLocation());
        }

        if (!$this->destinationDir->canWrite()) {
            throw new BuildException("Can not write to the specified destdir!", $this->getLocation());
        }

        if (!is_array($this->domains) || (count($this->domains) == 0)) {
            throw new BuildException("domains attribute must be set!", $this->getLocation());
        }

        if (null === $this->charset) {
            throw new BuildException("charset attribute must be set!", $this->getLocation());
        }
    }
}

?>