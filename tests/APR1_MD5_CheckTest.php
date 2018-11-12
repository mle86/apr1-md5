<?php

use WhiteHat101\Crypt\APR1_MD5;

class APR1_MD5_CheckTest extends PHPUnit_Framework_TestCase {

    public function knownHashMatches() {
        return array(
            // syntax: array(knownPassword, knownHash)
            array('WhiteHat101', '$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/'),
            array('apache',      '$apr1$rOioh4Wh$bVD3DRwksETubcpEH90ww0'),
            array('ChangeMe1',   '$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1'),
        );
    }

    /**
     * @dataProvider knownHashMatches
     */
    public function testCheckHashMatch($knownHash, $correctPassword) {
        $this->assertTrue(
            APR1_MD5::check($correctPassword, $knownHash)
        );
    }

}
