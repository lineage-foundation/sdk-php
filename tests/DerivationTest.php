<?php

namespace Lineage\Tests;

use Lineage\Functions\Bip32;
use Lineage\Functions\KeyHelpers;

class DerivationTest extends VectorTestCase
{
    public function testDerivation(): void
    {
        $v = $this->vector('derivation');

        $seed = Bip32::mnemonicToSeed($v['mnemonic'], $v['passphrase']);
        $master = Bip32::masterXprv($seed);
        $this->assertSame($v['xprivkey'], $master, 'master xprv');

        foreach ($v['depths'] as $d) {
            $child = Bip32::childXprv($master, (int)$d['depth']);
            $this->assertSame($d['childXprv'], $child, "childXprv d={$d['depth']}");

            $edSeed = substr($child, 0, 32);
            $this->assertSame($d['edSeed32'], sodium_bin2hex($edSeed), "edSeed d={$d['depth']}");

            $kp = KeyHelpers::keypairFromSeed($edSeed);
            $this->assertSame($d['publicKey'], sodium_bin2hex($kp['publicKey']), "publicKey d={$d['depth']}");
            $this->assertSame($d['secretKey'], sodium_bin2hex($kp['secretKey']), "secretKey d={$d['depth']}");
            $this->assertSame($d['address'], KeyHelpers::constructAddress($kp['publicKey']), "address d={$d['depth']}");
        }
    }

    public function testDeriveKeypairMatchesVector(): void
    {
        $v = $this->vector('derivation');

        foreach ($v['depths'] as $d) {
            $kp = KeyHelpers::deriveKeypair($v['mnemonic'], $v['passphrase'], (int)$d['depth']);
            $this->assertSame($d['publicKey'], sodium_bin2hex($kp['publicKey']), "deriveKeypair publicKey d={$d['depth']}");
            $this->assertSame($d['address'], $kp['address'], "deriveKeypair address d={$d['depth']}");
        }
    }
}
