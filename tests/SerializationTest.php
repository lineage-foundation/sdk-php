<?php

namespace Lineage\Tests;

use Lineage\Serialization;

class SerializationTest extends VectorTestCase
{
    public function testSignablePreimage(): void
    {
        $v = $this->vector('signable');

        $s = '';
        foreach ($v['txOuts'] as $o) {
            $s .= Serialization::json($o);
        }
        $s .= Serialization::json($v['outPoint']);

        $this->assertSame($v['preimage'], $s);
    }

    public function testOutPointBuilderMatchesVector(): void
    {
        $v = $this->vector('signable');

        $outPoint = Serialization::outPoint($v['outPoint']['t_hash'], $v['outPoint']['n']);

        $this->assertSame($v['outPoint'], $outPoint);
        $this->assertSame(Serialization::json($v['outPoint']), Serialization::json($outPoint));
    }

    public function testTxOutBuilderMatchesVector(): void
    {
        $v = $this->vector('signable');
        $vectorTxOut = $v['txOuts'][0];

        $txOut = Serialization::txOut(
            Serialization::assetToken($vectorTxOut['value']['Token']),
            $vectorTxOut['locktime'],
            $vectorTxOut['script_public_key']
        );

        $this->assertSame($vectorTxOut, $txOut);
        $this->assertSame(Serialization::json($vectorTxOut), Serialization::json($txOut));
    }

    public function testAssetTokenShape(): void
    {
        $this->assertSame('{"Token":1000}', Serialization::json(Serialization::assetToken(1000)));
    }

    public function testAssetItemShapeWithMetadata(): void
    {
        $asset = Serialization::assetItem(5, 'abc123', 'hello');

        $this->assertSame(
            '{"Item":{"amount":5,"genesis_hash":"abc123","metadata":"hello"}}',
            Serialization::json($asset)
        );
    }

    public function testAssetItemShapeWithNullMetadata(): void
    {
        $asset = Serialization::assetItem(5, 'abc123', null);

        $this->assertSame(
            '{"Item":{"amount":5,"genesis_hash":"abc123","metadata":null}}',
            Serialization::json($asset)
        );
    }
}
