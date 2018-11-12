<?php

use WhiteHat101\Crypt\APR1_MD5;

class APR1_MD5_HashTest extends PHPUnit_Framework_TestCase {

    public function knownHashResults() {
        return array(
            // syntax: array(password, salt, expectedHashOutput)
            array('WhiteHat101', 'HIcWIbgX', '$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/'),
            array('apache',      'rOioh4Wh', '$apr1$rOioh4Wh$bVD3DRwksETubcpEH90ww0'),
            array('ChangeMe1',   'PVWlTz/5', '$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1'),

            // Test some awkward inputs:
            array('ChangeMe1', '',                   '$apr1$$DbHa0iITto8vNFPlkQsBX1'),  // blank salt
            array('ChangeMe1', 'PVWlTz/50123456789', '$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1'),  // long salt
        );
    }

    /**
     * @dataProvider knownHashResults
     */
    public function testHashResult($password, $salt, $expectedHashOutput) {
        $this->assertEquals(
            $expectedHashOutput,
            APR1_MD5::hash($password,$salt)
        );
    }

    /**
     * @depends testHashResult
     */
    public function testHash__nullSalt() {
        $hash = APR1_MD5::hash('');
        $this->assertEquals(37, strlen($hash));
    }

    // a null password gets coerced into the blank string.
    // is this sensible?
    /**
     * @depends testHashResult
     */
    public function testHash_null_nullSalt() {
        $hash = APR1_MD5::hash(null);
        $this->assertEquals(37, strlen($hash));
    }

}
