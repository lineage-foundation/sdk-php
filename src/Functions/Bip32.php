<?php

namespace Lineage\Functions;

use Elliptic\EC;
use Normalizer;

/**
 * Bitcore-compatible BIP39 seed derivation and BIP32 hardened key derivation.
 *
 * This is a byte-for-byte port of the canonical sdk-js / sdk-go derivation:
 * the ed25519 seed used elsewhere is the first 32 ASCII bytes of the xprv
 * Base58Check string (non-standard, but what the reference wallets do).
 */
class Bip32
{
    /** bitcore mainnet BIP32 private version bytes (0x0488ADE4). */
    private const MAINNET_XPRV_VERSION = 0x0488ADE4;

    private const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    /** secp256k1 group order n. */
    private const SECP256K1_N = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';

    /**
     * BIP39 seed: PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic".NFKD(passphrase), 2048, 64).
     * Returns 64 raw bytes.
     */
    public static function mnemonicToSeed(string $mnemonic, string $passphrase): string
    {
        $m = self::nfkd($mnemonic);
        $p = 'mnemonic' . self::nfkd($passphrase);

        return hash_pbkdf2('sha512', $m, $p, 2048, 64, true);
    }

    /**
     * Build the BIP32 master extended private key from a 64-byte seed and
     * return it as a bitcore mainnet Base58Check xprv string.
     */
    public static function masterXprv(string $seed64): string
    {
        $i = hash_hmac('sha512', $seed64, 'Bitcoin seed', true);
        $key = substr($i, 0, 32);
        $chainCode = substr($i, 32, 32);

        return self::serializeXprv(
            depth: 0,
            parentFingerprint: "\x00\x00\x00\x00",
            childNumber: 0,
            chainCode: $chainCode,
            key: $key
        );
    }

    /**
     * Hardened CKDpriv: derive the child xprv at (index | 0x80000000) from a
     * parent xprv Base58Check string.
     */
    public static function childXprv(string $parentXprv, int $index): string
    {
        $parent = self::parseXprv($parentXprv);
        $i = ($index | 0x80000000) & 0xFFFFFFFF;

        // data = 0x00 . parentKey . ser32be(i)
        $data = "\x00" . $parent['key'] . self::ser32be($i);
        $I = hash_hmac('sha512', $data, $parent['chainCode'], true);

        $il = substr($I, 0, 32);
        $childChainCode = substr($I, 32, 32);

        // childKey = (be(il) + be(parentKey)) mod n
        $n = gmp_init(self::SECP256K1_N, 16);
        $sum = gmp_mod(
            gmp_add(
                gmp_import($il, 32, GMP_MSW_FIRST | GMP_BIG_ENDIAN),
                gmp_import($parent['key'], 32, GMP_MSW_FIRST | GMP_BIG_ENDIAN)
            ),
            $n
        );
        $childKey = self::gmpTo32Bytes($sum);

        // parentFingerprint = HASH160(compressed parent pubkey)[:4]
        $fp = substr(self::hash160(self::compressedPubKey($parent['key'])), 0, 4);

        return self::serializeXprv(
            depth: $parent['depth'] + 1,
            parentFingerprint: $fp,
            childNumber: $i,
            chainCode: $childChainCode,
            key: $childKey
        );
    }

    /**
     * Serialize a BIP32 extended private key to a bitcore mainnet Base58Check string.
     */
    private static function serializeXprv(
        int $depth,
        string $parentFingerprint,
        int $childNumber,
        string $chainCode,
        string $key
    ): string {
        $payload = self::ser32be(self::MAINNET_XPRV_VERSION)
            . chr($depth & 0xFF)
            . $parentFingerprint
            . self::ser32be($childNumber)
            . $chainCode
            . "\x00"
            . $key;

        return self::base58CheckEncode($payload);
    }

    /**
     * Parse a Base58Check xprv string back into its components.
     *
     * @return array{version:int,depth:int,parentFingerprint:string,childNumber:int,chainCode:string,key:string}
     */
    private static function parseXprv(string $xprv): array
    {
        $payload = self::base58CheckDecode($xprv);

        return [
            'version'           => self::deser32be(substr($payload, 0, 4)),
            'depth'             => ord($payload[4]),
            'parentFingerprint' => substr($payload, 5, 4),
            'childNumber'       => self::deser32be(substr($payload, 9, 4)),
            'chainCode'         => substr($payload, 13, 32),
            // byte 45 is the 0x00 private-key marker; key is bytes 46..77
            'key'               => substr($payload, 46, 32),
        ];
    }

    /**
     * Base58Check encode: append first 4 bytes of double-SHA256 as checksum,
     * then Base58 encode.
     */
    public static function base58CheckEncode(string $payload): string
    {
        $checksum = substr(hash('sha256', hash('sha256', $payload, true), true), 0, 4);

        return self::base58Encode($payload . $checksum);
    }

    private static function base58CheckDecode(string $encoded): string
    {
        $raw = self::base58Decode($encoded);
        return substr($raw, 0, -4);
    }

    private static function base58Encode(string $bytes): string
    {
        // Preserve leading zero bytes as leading '1's.
        $leadingZeros = 0;
        $len = strlen($bytes);
        while ($leadingZeros < $len && $bytes[$leadingZeros] === "\x00") {
            $leadingZeros++;
        }

        $num = ($len === $leadingZeros)
            ? gmp_init(0)
            : gmp_import(substr($bytes, $leadingZeros), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        $out = '';
        $fifty8 = gmp_init(58);
        while (gmp_cmp($num, 0) > 0) {
            [$num, $rem] = gmp_div_qr($num, $fifty8);
            $out = self::BASE58_ALPHABET[gmp_intval($rem)] . $out;
        }

        return str_repeat('1', $leadingZeros) . $out;
    }

    private static function base58Decode(string $encoded): string
    {
        $num = gmp_init(0);
        $fifty8 = gmp_init(58);
        $len = strlen($encoded);
        for ($i = 0; $i < $len; $i++) {
            $pos = strpos(self::BASE58_ALPHABET, $encoded[$i]);
            if ($pos === false) {
                throw new \InvalidArgumentException('Invalid base58 character: ' . $encoded[$i]);
            }
            $num = gmp_add(gmp_mul($num, $fifty8), $pos);
        }

        $bytes = gmp_cmp($num, 0) === 0
            ? ''
            : gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        // Restore leading zero bytes for each leading '1'.
        $leadingOnes = 0;
        while ($leadingOnes < $len && $encoded[$leadingOnes] === '1') {
            $leadingOnes++;
        }

        return str_repeat("\x00", $leadingOnes) . $bytes;
    }

    /** Compressed secp256k1 public key (33 bytes) for a 32-byte private key. */
    private static function compressedPubKey(string $key32): string
    {
        $ec = new EC('secp256k1');
        $priv = $ec->keyFromPrivate(bin2hex($key32), 'hex');
        $hex = $priv->getPublic(true, 'hex');

        return hex2bin(str_pad($hex, 66, '0', STR_PAD_LEFT));
    }

    /** HASH160 = RIPEMD160(SHA256(data)). */
    private static function hash160(string $data): string
    {
        return hash('ripemd160', hash('sha256', $data, true), true);
    }

    /** 4-byte big-endian serialization of a uint32. */
    private static function ser32be(int $value): string
    {
        return pack('N', $value & 0xFFFFFFFF);
    }

    private static function deser32be(string $bytes): int
    {
        return unpack('N', $bytes)[1];
    }

    /** Left-pad a GMP integer to a 32-byte big-endian string. */
    private static function gmpTo32Bytes(\GMP $value): string
    {
        if (gmp_cmp($value, 0) === 0) {
            return str_repeat("\x00", 32);
        }
        $bytes = gmp_export($value, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        return str_pad($bytes, 32, "\x00", STR_PAD_LEFT);
    }

    /** NFKD normalization; no-op when ext-intl is unavailable (ASCII inputs). */
    private static function nfkd(string $s): string
    {
        if (class_exists(Normalizer::class)) {
            $normalized = Normalizer::normalize($s, Normalizer::FORM_KD);
            if ($normalized !== false) {
                return $normalized;
            }
        }

        return $s;
    }
}
