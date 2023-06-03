<?php

namespace SimpleID\Util\UI;

use PHPUnit\Framework\TestCase;
use SimpleID\Util\UI\Template;

class AttachmentTest extends TestCase {
    public function testAttachments() {
        $f3 = \Base::instance();
        $tpl = Template::instance();

        $tpl->addAttachment('css', [ 'abc' ]);
        $this->assertEquals('abc', $f3->get('attachments.css.0.0'));

        // F3 instances are re-used, so we need to clean it up
        \Registry::clear(\Base::class);
        \Registry::clear(Template::class);
    }

    public function testMergeAttachments() {
        $f3 = \Base::instance();
        $tpl = Template::instance();
        $builder = new UIBuilder();

        $builder->addAttachment('css', [ 'abc' ]);

        $tpl->addAttachment('css', [ 'def' ]);
        $tpl->mergeAttachments($builder);

        $this->assertEquals(2, count($f3->get('attachments.css')));

        // F3 instances are re-used, so we need to clean it up
        \Registry::clear(\Base::class);
        \Registry::clear(Template::class);
    }
}

?>