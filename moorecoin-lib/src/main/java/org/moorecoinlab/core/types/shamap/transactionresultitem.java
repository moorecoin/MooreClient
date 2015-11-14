package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.hash.prefixes.hashprefix;
import org.moorecoinlab.core.hash.prefixes.prefix;
import org.moorecoinlab.core.serialized.binaryserializer;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.types.known.tx.result.transactionresult;

public class transactionresultitem extends shamapitem<transactionresult> {
    transactionresult result;

    public transactionresultitem(transactionresult result) {
        this.result = result;
    }

    @override
    void tobytessink(bytessink sink) {
        binaryserializer write = new binaryserializer(sink);
        write.addlengthencoded(result.txn);
        write.addlengthencoded(result.meta);
    }

    @override
    public shamapitem<transactionresult> copy() {
        // that's ok right ;) these bad boys are immutable anyway
        return this;
    }

    @override
    public prefix hashprefix() {
        return hashprefix.txnode;
    }
}
