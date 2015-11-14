package org.moorecoinlab.core.hash.prefixes;

import org.moorecoinlab.core.uint.uint32;

public enum hashprefix implements prefix {
    transactionid(0x54584e00),
    // transaction plus metadata
    txnode(0x534e4400),
    // account state
    leafnode(0x4d4c4e00),
    // inner node in tree
    innernode(0x4d494e00),
    // ledger master data for signing
    ledgermaster(0x4c575200),
    // inner transaction to sign
    txsign(0x53545800),
    // validation for signing
    validation(0x56414c00),
    // proposal for signing
    proposal(0x50525000);

    public uint32 uint32;
    public byte[] bytes;

    @override
    public byte[] bytes() {
        return bytes;
    }

    hashprefix(long i) {
        uint32 = new uint32(i);
        bytes = uint32.tobytearray();
    }
}
