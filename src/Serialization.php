<?php

namespace Lineage;

/**
 * Serialization builds the associative-array shapes for the /v1 wire structs
 * and JSON-encodes them to byte-identical output vs sdk-js's JSON.stringify.
 *
 * Field order/tags are load-bearing: these structs' compact JSON encoding
 * forms part of the signable-hash preimage and must be byte-identical across
 * every SDK (sdk-js, sdk-go, sdk-php). Do not sort keys and do not omit null
 * fields — PHP associative arrays preserve insertion order, so the array
 * builders below must build keys in the exact order the wire struct expects.
 */
class Serialization
{
    /**
     * Encode a value the same way sdk-js's JSON.stringify does: forward
     * slashes and non-ASCII characters are left unescaped, and key order /
     * null fields are preserved exactly as built.
     */
    public static function json($value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * OutPoint identifies a transaction output: the hash of the transaction
     * that created it and the index into that transaction's outputs.
     * Matches sdk-go's OutPoint / sdk-js's IOutPoint: {"t_hash","n"}.
     */
    public static function outPoint(string $tHash, int $n): array
    {
        return [
            't_hash' => $tHash,
            'n' => $n,
        ];
    }

    /**
     * TxOut is a single transaction output: the asset it carries, an
     * optional locktime, and the destination script public key (address).
     * Matches sdk-go's TxOut / sdk-js's ITxOut: {"value","locktime",
     * "script_public_key"}.
     */
    public static function txOut(array $value, int $locktime, string $scriptPublicKey): array
    {
        return [
            'value' => $value,
            'locktime' => $locktime,
            'script_public_key' => $scriptPublicKey,
        ];
    }

    /**
     * Token asset: serde's externally-tagged enum shape for
     * prime::primitives::asset::Asset::Token -> {"Token":<amount>}.
     */
    public static function assetToken(int $amount): array
    {
        return [
            'Token' => $amount,
        ];
    }

    /**
     * Item asset: serde's externally-tagged enum shape for
     * prime::primitives::asset::Asset::Item ->
     * {"Item":{"amount","genesis_hash","metadata"}}.
     * $metadata is nullable and is always present (never omitted).
     */
    public static function assetItem(int $amount, string $genesisHash, ?string $metadata): array
    {
        return [
            'Item' => [
                'amount' => $amount,
                'genesis_hash' => $genesisHash,
                'metadata' => $metadata,
            ],
        ];
    }

    /**
     * DruidExpectation: one leg of a two-way (DRUID) trade. Matches
     * sdk-go's DruidExpectation / sdk-js's IDruidExpectation:
     * {"from","to","asset"}.
     */
    public static function druidExpectation(string $from, string $to, array $asset): array
    {
        return [
            'from' => $from,
            'to' => $to,
            'asset' => $asset,
        ];
    }

    /**
     * DruidInfo carries the DRUID (two-way trade) metadata attached to a
     * transaction at construction time: {"druid","participants",
     * "expectations"}. genesis_hash/fees are added downstream at submission
     * time, not here.
     */
    public static function druidInfo(string $druid, int $participants, array $expectations): array
    {
        return [
            'druid' => $druid,
            'participants' => $participants,
            'expectations' => $expectations,
        ];
    }
}
