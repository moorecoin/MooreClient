package org.moorecoinlab.core.types.known.tx.txns;

import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.amount;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.types.known.tx.transaction;

public class addreferee extends transaction {
    public addreferee() {
        super(transactiontype.addreferee);
    }
    public accountid destination() {return get(accountid.destination);}
    public amount amount() {return get(amount.amount);}
    public void amount(amount val) {put(field.amount, val);}
    public void destination(accountid val) {put(field.destination, val);}
}
