<?php

use WhiteHat101\Crypt\APR1_MD5;

class APR1_MD5_CheckTest extends PHPUnit_Framework_TestCase {

    public function knownHashMatches() {
        return array(
            // syntax: array(knownHash, correctPassword)
            array('$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/', 'WhiteHat101'),
            array('$apr1$rOioh4Wh$bVD3DRwksETubcpEH90ww0', 'apache'),
            array('$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1', 'ChangeMe1'),
        );
    }

    public function knownHashMismatches() {
        return array(
            // syntax: array(knownHash, incorrectPassword)
            array('$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/', 'WhiteHat1011'),
            array('$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/', 'WhiteHat10x'),
            array('$apr1$rOioh4Wh$bVD3DRwksETubcpEH90ww0', 'ap4che'),
            array('$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1', 'ChangeMe1' . "\x00"),
            array('$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1', 'ChangeMe2'),
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

    /**
     * @dataProvider knownHashMismatches
     */
    public function testCheckHashMismatch($knownHash, $incorrectPassword) {
        $this->assertFalse(
            APR1_MD5::check($incorrectPassword, $knownHash)
        );
    }

}
