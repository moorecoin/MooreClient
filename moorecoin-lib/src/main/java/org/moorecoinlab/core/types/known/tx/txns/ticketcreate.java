package org.moorecoinlab.core.types.known.tx.txns;


import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.types.known.tx.transaction;

public class ticketcreate extends transaction {
    public ticketcreate() {
        super(transactiontype.ticketcreate);
    }
}
