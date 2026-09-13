<?php

namespace Lineage\Functions;

use FurqanSiddiqui\BIP39\BIP39;
use Lineage\Exceptions\KeypairNotDecryptedException;
use Lineage\Serialization;

class KeyHelpers
{
    /**
     * The BIP39 passphrase every keypair derivation uses. sdk-js's
     * generateMasterKey/mgmtClient.initNew et al. never pass a BIP39
     * passphrase (it defaults to ''); the wallet's own passphrase only ever
     * encrypts the keystore (mnemonic and individual keypairs) at rest, via
     * passphraseKey(). Fixing this avoids conflating the two and matches
     * sdk-go's bip39Passphrase constant.
     */
    private const BIP39_PASSPHRASE = '';

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

    /**
     * Derive and encrypt the next unused keypair: starting at
     * index = count($existingAddresses), derive keypairs at increasing
     * indices until one whose address isn't already in $existingAddresses is
     * found, matching sdk-js's generateNewKeypairAndAddress / sdk-go's
     * GetNewKeypair. $passphraseKey must already be a derived secretbox key
     * (e.g. from passphraseKey()), not a raw passphrase — the returned
     * nonce/save are produced by encryptKeypair(), so the result decrypts
     * via decryptKeypair() with that same $passphraseKey.
     */
    public static function getNewKeypair(string $mnemonic, string $passphraseKey, array $existingAddresses = []): array
    {
        $index = count($existingAddresses);

        do {
            $keypair = self::deriveKeypair($mnemonic, self::BIP39_PASSPHRASE, $index);
            $address = $keypair['address'];
            $index++;
        } while (in_array($address, $existingAddresses, true));

        $encrypted = self::encryptKeypair($keypair['publicKey'], $keypair['secretKey'], $passphraseKey);

        return [
            'address' => $address,
            'nonce'   => $encrypted['nonce'],
            'save'    => $encrypted['save'],
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

    /**
     * Seal an arbitrary string under a passphrase-derived key, matching
     * sdk-go's sealMnemonic: sodium_crypto_secretbox with a fresh
     * v4-UUID-derived nonce (same convention as encryptKeypair). Used by
     * Client::createWallet to seal the wallet's BIP39 mnemonic — this SDK
     * derives every keypair directly from the mnemonic (see getNewKeypair),
     * so the mnemonic itself, not a separate BIP32 master key, is the
     * reconstructable wallet state.
     *
     * @return array{nonce:string,save:string}
     */
    public static function encryptMnemonic(string $mnemonic, string $passphraseKey, ?string $nonce = null): array
    {
        $nonce ??= substr(self::generateUuidV4(), 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $save = sodium_crypto_secretbox($mnemonic, $nonce, $passphraseKey);

        return [
            'nonce' => $nonce,
            'save'  => sodium_bin2base64($save, SODIUM_BASE64_VARIANT_ORIGINAL),
        ];
    }

    /**
     * Open a mnemonic sealed by encryptMnemonic (or sdk-go's sealMnemonic).
     */
    public static function decryptMnemonic(string $save, string $nonce, string $passphraseKey): string
    {
        $decrypted = sodium_crypto_secretbox_open(
            sodium_base642bin($save, SODIUM_BASE64_VARIANT_ORIGINAL),
            $nonce,
            $passphraseKey
        );

        if ($decrypted === false) {
            throw new KeypairNotDecryptedException();
        }

        return $decrypted;
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

    public static function generateSeed(int $length = 12): string
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

    /**
     * The /v1 transaction input signable hash: sha3-256 of the concatenated
     * compact-JSON encoding of each of this input's consuming tx_outs
     * followed by the compact-JSON encoding of the previous out-point being
     * spent (or "null" if there is none). Matches sdk-go/sdk-js exactly —
     * see sdk-go/tx.go's constructTxInOutSignableHash.
     *
     * @param array|null $prevOut
     * @param array $txOuts
     */
    public static function constructTxInOutSignableHash(?array $prevOut, array $txOuts): string
    {
        $preimage = '';
        foreach ($txOuts as $txOut) {
            $preimage .= Serialization::json($txOut);
        }
        $preimage .= Serialization::json($prevOut);

        return hash('sha3-256', $preimage);
    }

    /**
     * Sign a signable hash. CRITICAL: signs the UTF-8 bytes of the 64-char
     * hex string representation of the hash, not the raw digest bytes —
     * this must match sdk-js's behaviour exactly.
     */
    public static function constructSignature(string $signableHashHex, string $secretKey): string
    {
        return sodium_bin2hex(sodium_crypto_sign_detached($signableHashHex, $secretKey));
    }

    /**
     * The signable hash of an Item/Token asset (used e.g. for genesis
     * hashes): sha3-256 of "Token:<amount>" or "Item:<amount>".
     */
    public static function constructItemAssetSignableHash(array $asset): string
    {
        $preimage = isset($asset['Token']) ? 'Token:' . $asset['Token'] : 'Item:' . $asset['Item']['amount'];

        return hash('sha3-256', $preimage);
    }

    public static function constructAddress(string $publicKeyBytes): string
    {
        return hash('sha3-256', $publicKeyBytes);
    }

    public static function getFormattedOutPointString(array $outpoint): string
    {
        return "{$outpoint['n']}-{$outpoint['t_hash']}";
    }
}
