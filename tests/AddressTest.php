<?php
namespace Lineage\Tests;
use Lineage\Functions\KeyHelpers;
class AddressTest extends VectorTestCase {
    public function testConstructAddress(): void {
        foreach ($this->vector('derivation')['depths'] as $d) {
            $pub = sodium_hex2bin($d['publicKey']);
            $this->assertSame($d['address'], KeyHelpers::constructAddress($pub));
        }
    }
}
