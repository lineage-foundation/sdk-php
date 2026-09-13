<?php

namespace Lineage\Tests;

use Lineage\Functions\TxBuilder;
use Lineage\Serialization;

class PaymentTxTest extends VectorTestCase
{
    public function testCreatePaymentTxMatchesVector(): void
    {
        $v = $this->vector('payment');
        $derivation = $this->vector('derivation');

        $senderSecretKeyHex = null;
        foreach ($derivation['depths'] as $d) {
            if ($d['publicKey'] === $v['senderPublicKey'] && $d['address'] === $v['senderAddress']) {
                $senderSecretKeyHex = $d['secretKey'];
                break;
            }
        }
        $this->assertNotNull(
            $senderSecretKeyHex,
            'no derivation.json entry matches senderPublicKey/senderAddress from payment.json'
        );

        $keyPairs = [
            $v['senderAddress'] => [
                'publicKey' => sodium_hex2bin($v['senderPublicKey']),
                'secretKey' => sodium_hex2bin($senderSecretKeyHex),
            ],
        ];

        $tx = TxBuilder::createPaymentTx(
            $v['paymentAddress'],
            $v['paymentAsset'],
            $v['excessAddress'],
            $v['fetchBalanceResponse'],
            $keyPairs,
            (int) $v['locktime']
        );

        $expected = $v['createTxPayload']['createTx'];

        $this->assertSame(Serialization::json($expected), Serialization::json($tx));
    }
}
