package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.stobject;
import org.moorecoinlab.core.hash.prefixes.hashprefix;
import org.moorecoinlab.core.hash.prefixes.prefix;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.types.known.sle.ledgerentry;

public class ledgerentryitem extends shamapitem<ledgerentry> {
    public ledgerentryitem(ledgerentry entry) {
        this.entry = entry;
    }

    public ledgerentry entry;

    @override
    void tobytessink(bytessink sink) {
        entry.tobytessink(sink);
    }

    @override
    public shamapitem<ledgerentry> copy() {
        stobject object = stobject.translate.frombytes(entry.tobytes());
        ledgerentry le = (ledgerentry) object;
        // todo: what about other auxiliary (non serialized) fields
        le.index(entry.index());
        return new ledgerentryitem(le);
    }

    @override
    public prefix hashprefix() {
        return hashprefix.leafnode;
    }
}
