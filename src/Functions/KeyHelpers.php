<?php

namespace Lineage\Functions;

use FurqanSiddiqui\BIP39\BIP39;
use Lineage\Exceptions\KeypairNotDecryptedException;

class KeyHelpers
{
    /**
     * Returns array with seed phrase, nonce, save
     */
    public static function initialiseFromPassphrase(string $passPhraseHash, ?string $seedPhrase = null): array
    {
        $generatedSeed = $seedPhrase ?? self::generateSeed();
        $newMasterKey = self::generateMasterKey($generatedSeed, $passPhraseHash);

        $masterKeyEncryptedAndNonce = self::encryptMasterKey($newMasterKey, $passPhraseHash);
        $masterKeyEncryptedBase64 = $masterKeyEncryptedAndNonce['master_key_encrypted'];
        $nonceHex = $masterKeyEncryptedAndNonce['nonce'];

        return [
            'seedPhrase'         => $generatedSeed,
            'masterKeyEncrypted' => $masterKeyEncryptedBase64,
            'nonce'              => $nonceHex,
        ];
    }

    private static function generateMasterKey(string $seed, string $passPhraseHash, int $depth = 0): string
    {
        $hash = hash_pbkdf2('sha512', $seed, $passPhraseHash, 2048 + $depth, 64);

        return substr(hash_hmac('sha512', $hash, 'Bitcoin seed'), 0, 64);
    }

    private static function getNonce(): string
    {
        return random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    }

    private static function encryptMasterKey(string $masterKey, string $passPhraseHash): array
    {
        $nonce = self::getNonce();

        $ciphertext = sodium_crypto_secretbox(
            $masterKey,
            $nonce,
            $passPhraseHash
        );

        return [
            'master_key_encrypted' => sodium_bin2base64($ciphertext, SODIUM_BASE64_VARIANT_ORIGINAL),
            'nonce'                => sodium_bin2hex($nonce),
        ];
    }

    /**
     * Derive the ed25519 keypair (and address) at the given hardened BIP32 index.
     *
     * The ed25519 seed is the first 32 bytes of the ASCII xprv Base58Check
     * string of the derived child key (matches sdk-js).
     *
     * @return array{publicKey:string,secretKey:string,address:string}
     */
    public static function deriveKeypair(string $mnemonic, string $passphrase, int $index): array
    {
        $master = Bip32::masterXprv(Bip32::mnemonicToSeed($mnemonic, $passphrase));
        $childXprv = Bip32::childXprv($master, $index);
        $edSeed = substr($childXprv, 0, SODIUM_CRYPTO_SIGN_SEEDBYTES);

        $keypair = self::keypairFromSeed($edSeed);
        $keypair['address'] = self::constructAddress($keypair['publicKey']);

        return $keypair;
    }

    public static function getNewKeypair(string $mnemonic, string $passPhrase, array $existingAddresses = []): array
    {
        $index = count($existingAddresses);

        do {
            $keypair = self::deriveKeypair($mnemonic, $passPhrase, $index);
            $address = $keypair['address'];
            $index++;
        } while (in_array($address, $existingAddresses, true));

        $nonce = self::getNonce();
        $save = sodium_crypto_secretbox($keypair['publicKey'] . $keypair['secretKey'], $nonce, $passPhrase);

        return [
            'address' => $address,
            'nonce'   => sodium_bin2hex($nonce),
            'save'    => sodium_bin2base64($save, SODIUM_BASE64_VARIANT_ORIGINAL),
        ];
    }

    /**
     * Decrypt a keystore record produced by encryptKeypair (or the sdk-js
     * equivalent). The nonce is used as-is: sdk-js stores the first 24 raw
     * characters of a v4 UUID as the secretbox nonce, so it is NOT hex or
     * base64 decoded here.
     */
    public static function decryptKeypair(
        string $save,
        string $nonce,
        string $passphraseKey
    ): array {
        $encryptedKeyPair = sodium_base642bin($save, SODIUM_BASE64_VARIANT_ORIGINAL);

        $decrypted = sodium_crypto_secretbox_open($encryptedKeyPair, $nonce, $passphraseKey);

        if ($decrypted === false) {
            throw new KeypairNotDecryptedException();
        }

        return [
            'publicKey' => substr($decrypted, 0, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES),
            'secretKey' => substr($decrypted, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES),
        ];
    }

    /**
     * Encrypt a keypair for storage, matching sdk-js's keystore record shape:
     * plaintext = publicKey(32) . secretKey(64), sealed with
     * sodium_crypto_secretbox under the passphraseKey, using a nonce that is
     * the first 24 raw bytes of a v4 UUID string.
     *
     * @return array{nonce:string,save:string}
     */
    public static function encryptKeypair(
        string $publicKey,
        string $secretKey,
        string $passphraseKey,
        ?string $nonce = null
    ): array {
        $nonce ??= substr(self::generateUuidV4(), 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $save = sodium_crypto_secretbox($publicKey . $secretKey, $nonce, $passphraseKey);

        return [
            'nonce' => $nonce,
            'save'  => sodium_bin2base64($save, SODIUM_BASE64_VARIANT_ORIGINAL),
        ];
    }

    private static function generateUuidV4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12)
        );
    }

    public static function encryptTransaction(array $transaction, string $passPhrase): array
    {
        $nonce = self::getNonce();
        $encryptedStr = sodium_crypto_secretbox(json_encode($transaction), $nonce, $passPhrase);

        return [
            'druid' => $transaction['druid_info']['druid'],
            'nonce' => sodium_bin2hex($nonce),
            'save'  => sodium_bin2base64($encryptedStr, SODIUM_BASE64_VARIANT_ORIGINAL),
        ];
    }

    public static function decryptTransaction(array $encryptedTransaction, string $passPhrase): array
    {
        $decryptedTransaction = sodium_crypto_secretbox_open(
            sodium_base642bin($encryptedTransaction['save'], SODIUM_BASE64_VARIANT_ORIGINAL),
            sodium_hex2bin($encryptedTransaction['nonce']),
            $passPhrase
        );

        if (!$decryptedTransaction) {
            throw new KeypairNotDecryptedException();
        }

        return json_decode($decryptedTransaction, true);
    }

    /**
     * Derive the secretbox key from a passphrase, matching sdk-js's
     * getPassphraseBuffer: the ASCII of the first 32 hex characters of the
     * sha3-256 digest (NOT the raw digest bytes).
     */
    public static function passphraseKey(string $passphrase): string
    {
        return substr(hash('sha3-256', $passphrase), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    public static function getPassPhraseHash(string $passPhrase): string
    {
        return self::passphraseKey($passPhrase);
    }

    private static function generateSeed(int $length = 12): string
    {
        return implode(' ', BIP39::Generate($length)->words);
    }

    public static function createSignature(string $message, string $secretKey): string
    {
        return sodium_bin2hex(sodium_crypto_sign_detached($message, $secretKey));
    }

    public static function keypairFromSeed(string $seed32): array
    {
        $raw = sodium_crypto_sign_seed_keypair($seed32);
        return [
            'publicKey' => sodium_crypto_sign_publickey($raw),
            'secretKey' => sodium_crypto_sign_secretkey($raw),
        ];
    }

    public static function generateDRUID(): string
    {
        return 'DRUID0x' . self::getPassPhraseHash(sodium_bin2hex(random_bytes(32)));
    }

    public static function constructTransactionInputAddress(array $inputs): string
    {
        $signableTxIns = implode('-', array_map(function ($input) {
            $scriptSignature = $input['script_signature']['Pay2PkH'];
            $previousOutPoint = $input['previous_out'];

            $scriptStack = self::getPayToPublicKeyHashScript(
                checkData: $scriptSignature['signable_data'],
                signatureData: $scriptSignature['signature'],
                publicKeyData: $scriptSignature['public_key'],
                addressVersion: $scriptSignature['address_version']
            );

            $formattedScriptString = implode('-', array_map(fn($item) => "{$item['type']}:{$item['value']}", $scriptStack));
            $previousOutpointStr = $previousOutPoint ? self::getFormattedOutPointString($previousOutPoint) : 'null';

            return "$previousOutpointStr-$formattedScriptString";
        }, $inputs));

        return self::constructAddress($signableTxIns);
    }

    public static function constructAddress(string $publicKeyBytes): string
    {
        return hash('sha3-256', $publicKeyBytes);
    }

    public static function getFormattedOutPointString(array $outpoint): string
    {
        return "{$outpoint['n']}-{$outpoint['t_hash']}";
    }

    private static function getPayToPublicKeyHashScript(
        string $checkData,
        string $signatureData,
        string $publicKeyData,
        int $addressVersion = null
    ): array {
        return  [
            [
                'type'  => 'Bytes',
                'value' => $checkData,
            ],
            [
                'type'  => 'Signature',
                'value' => $signatureData,
            ],
            [
                'type'  => 'PubKey',
                'value' => $publicKeyData,
            ],
            [
                'type'  => 'Op',
                'value' => 'OP_DUP',
            ],
            [
                'type'  => 'Op',
                'value' => 'OP_HASH256',
            ],
            [
                'type'  => 'Bytes',
                'value' => self::constructAddress(sodium_hex2bin($publicKeyData)),
            ],
            [
                'type'  => 'Op',
                'value' => 'OP_EQUALVERIFY',
            ],
            [
                'type'  => 'Op',
                'value' => 'OP_CHECKSIG',
            ],
        ];
    }
}
