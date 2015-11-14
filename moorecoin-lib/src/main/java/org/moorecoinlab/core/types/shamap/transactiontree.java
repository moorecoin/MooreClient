package org.moorecoinlab.core.types.shamap;


import org.moorecoinlab.core.types.known.tx.result.transactionresult;

public class transactiontree extends shamap {
    public transactiontree() {
        super();
    }

    public transactiontree(boolean iscopy, int depth) {
        super(iscopy, depth);
    }

    @override
    protected shamapinner makeinnerofsameclass(int depth) {
        return new transactiontree(true, depth);
    }

    public void addtransactionresult(transactionresult tr) {
        transactionresultitem item = new transactionresultitem(tr);
        additem(tr.hash, item);
    }

    @override
    public transactiontree copy() {
        return (transactiontree) super.copy();
    }
}
