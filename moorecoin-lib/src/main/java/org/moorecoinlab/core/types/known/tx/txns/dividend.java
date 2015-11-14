package org.moorecoinlab.core.types.known.tx.txns;

import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.types.known.tx.transaction;
import org.moorecoinlab.core.uint.uint64;

/**
 * dividend data class
 */
public class dividend extends transaction{
    public dividend() {
        super(transactiontype.dividend);
    }

    public accountid destination() {return get(accountid.destination);}
    public uint64 dividendcoins(){return (uint64)get(field.dividendcoins);}
    public uint64 dividendcoinsvbc(){return (uint64)get(field.dividendcoinsvbc);}
}
