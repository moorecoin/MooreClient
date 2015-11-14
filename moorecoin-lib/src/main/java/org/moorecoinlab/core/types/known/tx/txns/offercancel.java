package org.moorecoinlab.core.types.known.tx.txns;


import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.types.known.tx.transaction;
import org.moorecoinlab.core.uint.uint32;

public class offercancel extends transaction {
    public offercancel() {
        super(transactiontype.offercancel);
    }
    public uint32 offersequence() {return get(uint32.offersequence);}
    public void offersequence(uint32 val) {put(field.offersequence, val);}

}
