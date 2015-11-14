package org.moorecoinlab.core.types.known.tx.txns;


import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.types.known.tx.transaction;

public class ticketcancel extends transaction {
    public ticketcancel() {
        super(transactiontype.ticketcancel);
    }
    public hash256 ticketid() {
        return get(hash256.ticketid);
    }
    public void ticketid(hash256 id) {
        put(hash256.ticketid, id);
    }
}
