<?php
namespace Lineage\Tests;

use Lineage\Functions\KeyHelpers;

class Ed25519Test extends VectorTestCase {
    public function testSign(): void {
        $v = $this->vector('signing');
        $kp = KeyHelpers::keypairFromSeed(sodium_hex2bin($v['seed32']));
        $this->assertSame($v['publicKey'], sodium_bin2hex($kp['publicKey']));
        $sig = KeyHelpers::createSignature($v['message'], $kp['secretKey']);
        $this->assertSame($v['signatureHex'], $sig);
    }
}
