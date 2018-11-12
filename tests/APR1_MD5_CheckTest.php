<?php

namespace WhiteHat101\Crypt\Tests;

use PHPUnit\Framework\TestCase;
use WhiteHat101\Crypt\APR1_MD5;

class APR1_MD5_CheckTest extends TestCase {

    public function knownHashMatches(): array {
        return [
            // syntax: array(knownHash, correctPassword)
            ['$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/', 'WhiteHat101'],
            ['$apr1$rOioh4Wh$bVD3DRwksETubcpEH90ww0', 'apache'],
            ['$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1', 'ChangeMe1'],
        ];
    }

    public function knownHashMismatches(): array {
        return [
            // syntax: array(knownHash, incorrectPassword)
            ['$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/', 'WhiteHat1011'],
            ['$apr1$HIcWIbgX$G9YqNkCVGlFAN63bClpoT/', 'WhiteHat10x'],
            ['$apr1$rOioh4Wh$bVD3DRwksETubcpEH90ww0', 'ap4che'],
            ['$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1', 'ChangeMe1' . "\x00"],
            ['$apr1$PVWlTz/5$SNkIVyogockgH65nMLn.W1', 'ChangeMe2'],
        ];
    }

    /**
     * @dataProvider knownHashMatches
     */
    public function testCheckHashMatch(string $knownHash, string $correctPassword) {
        $this->assertTrue(
            APR1_MD5::check($correctPassword, $knownHash)
        );
    }

    /**
     * @dataProvider knownHashMismatches
     */
    public function testCheckHashMismatch(string $knownHash, string $incorrectPassword) {
        $this->assertFalse(
            APR1_MD5::check($incorrectPassword, $knownHash)
        );
    }

}
