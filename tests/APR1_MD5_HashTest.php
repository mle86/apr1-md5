<?php

namespace WhiteHat101\Crypt\Tests;

use PHPUnit\Framework\TestCase;
use WhiteHat101\Crypt\APR1_MD5;

class APR1_MD5_HashTest extends TestCase {

    public function knownHashResults(): array {
        return [
            // syntax: array(password, salt, expectedHashOutput)
            ['WhiteHat101', 'HIcWIbgX', '$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/'],
            ['apache',      'rOioh4Wh', '$apr1$rOioh4Wh$bVD3DRwksETubcpEH90ww0'],
            ['ChangeMe1',   'PVWlTz/5', '$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1'],

            // Test some awkward inputs:
            ['ChangeMe1', '',                   '$apr1$$DbHa0iITto8vNFPlkQsBX1'],  // blank salt
            ['ChangeMe1', 'PVWlTz/50123456789', '$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1'],  // long salt
        ];
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
