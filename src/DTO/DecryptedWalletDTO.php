<?php

namespace Lineage\DTO;

/**
 * The decrypted state of an open wallet: the BIP39 mnemonic every keypair is
 * derived from (KeyHelpers::getNewKeypair/deriveKeypair). This SDK has no
 * separate BIP32 master-key object to hold on to — every keypair is
 * re-derived from the mnemonic on demand — so the mnemonic itself is the
 * wallet's whole recoverable state, matching sdk-go's Wallet.mnemonic.
 */
class DecryptedWalletDTO
{
    public function __construct(
        private string $mnemonic,
    ) {
    }

    public function formatForAPI(): array
    {
        return [
            'mnemonic' => $this->mnemonic,
        ];
    }

    public function getMnemonic(): string
    {
        return $this->mnemonic;
    }
}
