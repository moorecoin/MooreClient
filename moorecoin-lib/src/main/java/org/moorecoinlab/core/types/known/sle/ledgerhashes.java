package org.moorecoinlab.core.types.known.sle;


import org.moorecoinlab.core.vector256;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.uint.uint32;

public class ledgerhashes extends ledgerentry {
    public ledgerhashes() {
        super(ledgerentrytype.ledgerhashes);
    }

    public vector256 hashes() {
        return get(vector256.hashes);
    }

    public void hashes(vector256 hashes) {
        put(vector256.hashes, hashes);
    }

    public uint32 lastledgersequence() {
        return get(uint32.lastledgersequence);
    }
}
