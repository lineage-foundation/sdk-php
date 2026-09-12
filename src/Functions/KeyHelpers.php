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

    public static function decryptKeypair(
        string $encryptedKey,
        string $nonce,
        string $passPhrase
    ): array {
        $encryptedKeyPair = sodium_base642bin($encryptedKey, SODIUM_BASE64_VARIANT_ORIGINAL);
        $nonce = sodium_hex2bin($nonce);

        $decrypted = sodium_crypto_secretbox_open($encryptedKeyPair, $nonce, $passPhrase);

        if (!$decrypted) {
            throw new KeypairNotDecryptedException();
        }

        return [
            'publicKey' => substr($decrypted, 0, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES),
            'secretKey' => substr($decrypted, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES),
        ];
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

    public static function getPassPhraseHash(string $passPhrase): string
    {
        return substr(hash('sha3-256', $passPhrase), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
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
