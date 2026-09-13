<?php

namespace Lineage\Tests;

use Lineage\Functions\KeyHelpers;

class KeystoreTest extends VectorTestCase
{
    public function testDecryptKeypairMatchesSdkJsVector(): void
    {
        $v = $this->vector('keystore');

        $passphraseKey = KeyHelpers::passphraseKey($v['passphrase']);
        $this->assertSame(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            strlen($passphraseKey),
            'passphraseKey must be 32 raw bytes'
        );

        $keypair = KeyHelpers::decryptKeypair(
            $v['encrypted']['save'],
            $v['encrypted']['nonce'],
            $passphraseKey
        );

        $this->assertSame($v['plaintext']['publicKey'], sodium_bin2hex($keypair['publicKey']), 'publicKey');
        $this->assertSame($v['plaintext']['secretKey'], sodium_bin2hex($keypair['secretKey']), 'secretKey');
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $v = $this->vector('keystore');

        $passphraseKey = KeyHelpers::passphraseKey($v['passphrase']);
        $publicKey = sodium_hex2bin($v['plaintext']['publicKey']);
        $secretKey = sodium_hex2bin($v['plaintext']['secretKey']);

        // First 24 chars of a v4-style UUID, matching the sdk-js nonce shape.
        $nonce = 'a1b2c3d4-e5f6-4789-9abc-';

        $encrypted = KeyHelpers::encryptKeypair($publicKey, $secretKey, $passphraseKey, $nonce);

        $this->assertSame($nonce, $encrypted['nonce']);

        $decrypted = KeyHelpers::decryptKeypair($encrypted['save'], $encrypted['nonce'], $passphraseKey);

        $this->assertSame($v['plaintext']['publicKey'], sodium_bin2hex($decrypted['publicKey']), 'round-trip publicKey');
        $this->assertSame($v['plaintext']['secretKey'], sodium_bin2hex($decrypted['secretKey']), 'round-trip secretKey');
    }
}
