<?php

use Gettext\Generator\Generator;
use Gettext\Translations;

class PhpGenerator extends Generator {
    public function generateString(Translations $translations): string {
        $pluralForm = $translations->getHeaders()->getPluralForm();
        $pluralSize = is_array($pluralForm) ? ($pluralForm[0] - 1) : null;
        $lines = [];

        $lines[] = '<?php';
        $lines[] = '';
        $lines[] = 'return [';

        $counter = 1;

        //Translations
        foreach ($translations as $translation) {
            foreach ($translation->getComments() as $comment) {
                $lines[] = sprintf('# %s', $comment);
            }

            foreach ($translation->getExtractedComments() as $comment) {
                $lines[] = sprintf('#. %s', $comment);
            }

            foreach ($translation->getReferences() as $filename => $lineNumbers) {
                if (empty($lineNumbers)) {
                    $lines[] = sprintf('#: %s', $filename);
                    continue;
                }

                foreach ($lineNumbers as $number) {
                    $lines[] = sprintf('#: %s:%d', $filename, $number);
                }
            }

            if (count($translation->getFlags())) {
                $lines[] = sprintf('#, %s', implode(',', $translation->getFlags()->toArray()));
            }

            $prefix = $translation->isDisabled() ? '#~ ' : '';

            $key = var_export('string_' . $counter, true);
            $value = $translation->getOriginal();

            $lines[] = $key . ' => '. var_export($value, true) . ',';

            $lines[] = '';

            $counter++;
        }

        $lines[] = '];';
        $lines[] = '?>';

        return implode("\n", $lines);
    }

    /**
     * Add one or more lines depending whether the string is multiline or not.
     */
    private static function appendLines(array &$lines, string $prefix, string $name, string $value): void
    {
        $newLines = explode("\n", $value);
        $total = count($newLines);

        if ($total === 1) {
            $lines[] = sprintf('%s%s %s', $prefix, $name, self::encode($newLines[0]));

            return;
        }

        $lines[] = sprintf('%s%s ""', $prefix, $name);

        $last = $total - 1;
        foreach ($newLines as $k => $line) {
            if ($k < $last) {
                $line .= "\n";
            }

            $lines[] = self::encode($line);
        }
    }

    /**
     * Convert a string to its PO representation.
     */
    public static function encode(string $value): string
    {
        return '"'.strtr(
            $value,
            [
                "\x00" => '',
                '\\' => '\\\\',
                "\t" => '\t',
                "\r" => '\r',
                "\n" => '\n',
                '"' => '\\"',
            ]
        ).'"';
    }
}

?>