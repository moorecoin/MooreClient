package org.moorecoinlab.core.types.known.tx.txns;


import org.moorecoinlab.core.amount;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.types.known.tx.transaction;
import org.moorecoinlab.core.uint.uint32;

public class trustset extends transaction {
    public trustset() {
        super(transactiontype.trustset);
    }

    public uint32 qualityin() {return get(uint32.qualityin);}
    public uint32 qualityout() {return get(uint32.qualityout);}
    public amount limitamount() {return get(amount.limitamount);}
    public void qualityin(uint32 val) {put(field.qualityin, val);}
    public void qualityout(uint32 val) {put(field.qualityout, val);}
    public void limitamount(amount val) {put(field.limitamount, val);}
}
