<?php

namespace Lineage\Tests;

use Lineage\Functions\KeyHelpers;
use Lineage\Functions\TxBuilder;
use Lineage\Serialization;

class TwoWayConstructionTest extends VectorTestCase
{
    public function testCreate2WTxHalfMatchesVector(): void
    {
        $v = $this->vector('twoway');
        $input = $v['create2WTxHalf']['input'];
        $expected = $v['create2WTxHalf']['output'];

        $keyPairs = [];
        foreach ($v['fixedKeypairs']['ours'] as $kp) {
            $keyPairs[$kp['address']] = [
                'publicKey' => hex2bin($kp['public_key']),
                'secretKey' => hex2bin($kp['secret_key']),
            ];
        }

        // The vector's outputs pay the counterparty (receiverExpectation:
        // cf0067... pays a07ffc... Token 1050), while druid_info.expectations
        // carries this party's (senderExpectation: a07ffc... -> cf0067...
        // Item). So thisExpectation=senderExpectation, counterExpectation=receiverExpectation.
        $tx = TxBuilder::create2WTxHalf(
            $v['druid'],
            $input['senderExpectation'],
            $input['receiverExpectation'],
            $input['fetchBalanceResponse'],
            $keyPairs,
            $input['excessAddress'],
            (int) $input['locktime']
        );

        $this->assertSame(Serialization::json($expected['druid_info']), Serialization::json($tx['druid_info']));
        $this->assertSame(Serialization::json($expected['outputs']), Serialization::json($tx['outputs']));
        $this->assertSame(Serialization::json($expected['inputs']), Serialization::json($tx['inputs']));
    }

    public function testConstructTxInsAddressMatchesVector(): void
    {
        $v = $this->vector('twoway');
        $address = KeyHelpers::constructTxInsAddress($v['constructTxInsAddress']['input']);

        $this->assertSame($v['constructTxInsAddress']['address'], $address);
    }

    public function testGenerateDRUIDFormat(): void
    {
        $druid = KeyHelpers::generateDRUID();

        $this->assertMatchesRegularExpression('/^DRUID0x[0-9a-f]{32}$/', $druid);
    }
}
