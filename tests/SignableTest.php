<?php

namespace Lineage\Tests;

use Lineage\Functions\KeyHelpers;
use Lineage\Serialization;

class SignableTest extends VectorTestCase
{
    public function testSignable(): void
    {
        $sv = $this->vector('signable');
        $sg = $this->vector('signing');

        $hash = KeyHelpers::constructTxInOutSignableHash($sv['outPoint'], $sv['txOuts']);
        $this->assertSame($sv['signableHash'], $hash);

        $kp = KeyHelpers::keypairFromSeed(sodium_hex2bin($sg['seed32']));
        $this->assertSame($sv['signatureHex'], KeyHelpers::constructSignature($hash, $kp['secretKey']));

        $this->assertSame($sv['assetTokenHash'], KeyHelpers::constructItemAssetSignableHash(Serialization::assetToken(1000)));
    }
}
