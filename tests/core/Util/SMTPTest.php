<?php

namespace SimpleID\Util;

use \Base;
use SimpleID\Util\UI\Template;
use PHPUnit\Framework\TestCase;

class SMTPTest extends TestCase {
    protected function isConfigured() {
        return (getenv('SIMPLEID_TEST_SMTP_HOST') !== false)
            && (getenv('SIMPLEID_TEST_SMTP_POST') !== false)
            && (getenv('SIMPLEID_TEST_SMTP_SCHEME') !== false)
            && (getenv('SIMPLEID_TEST_SMTP_USER') !== false)
            && (getenv('SIMPLEID_TEST_SMTP_PW') !== false);
    }

    public function testSendMail() {
        if (!$this->isConfigured()) {
            $this->markTestSkipped('SMTP server not configured');
            return;
        }

        $tpl = Template::instance();
        $f3 = Base::instance();
        $smtp = new SMTP(getenv('SIMPLEID_TEST_SMTP_HOST'),
            getenv('SIMPLEID_TEST_SMTP_POST'),
            getenv('SIMPLEID_TEST_SMTP_SCHEME'),
            getenv('SIMPLEID_TEST_SMTP_USER'),
            getenv('SIMPLEID_TEST_SMTP_PW'));

        $f3->mset(['UI' => 'www/html/,www/upgrade/', 'PREFIX' => 'intl.']);
        $f3->mset(['FALLBACK' => 'en', 'LOCALES' => 'www/locale/']);
        $f3->set('layout', 'mail/test.md');
        $f3->set('mail_footer', $f3->get('intl.common.mail.footer', ['test-recipient@simpleid.org', 'SimpleID']));

        $message = [
            'html' => $tpl->render('mail.html'),
            'text' => $tpl->render('mail.txt')
        ];

        $smtp->set('From', 'test-sender@simpleid.org');
        $smtp->set('To', 'test-recipient@simpleid.org');
        $smtp->set('Subject', $tpl->getReturnValue('subject'));
        $result = $smtp->send($message);

        $this->assertTrue($result);
    }
}
?>