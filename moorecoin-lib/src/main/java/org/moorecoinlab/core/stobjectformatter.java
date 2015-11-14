package org.moorecoinlab.core;


import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.types.known.sle.ledgerentry;
import org.moorecoinlab.core.types.known.sle.ledgerhashes;
import org.moorecoinlab.core.types.known.sle.entries.accountroot;
import org.moorecoinlab.core.types.known.sle.entries.directorynode;
import org.moorecoinlab.core.types.known.sle.entries.offer;
import org.moorecoinlab.core.types.known.sle.entries.ripplestate;
import org.moorecoinlab.core.types.known.tx.transaction;
import org.moorecoinlab.core.types.known.tx.result.affectednode;
import org.moorecoinlab.core.types.known.tx.result.transactionmeta;
import org.moorecoinlab.core.types.known.tx.txns.*;

public class stobjectformatter {
    public static stobject doformatted(stobject source) {
        // this would need to go before the test that just checks
        // for ledgerentrytype
        if (affectednode.isaffectednode(source)) {
            return new affectednode(source);
        }

        if (transactionmeta.istransactionmeta(source)) {
            transactionmeta meta = new transactionmeta();
            meta.fields = source.fields;
            return meta;
        }

        ledgerentrytype ledgerentrytype = stobject.ledgerentrytype(source);
        if (ledgerentrytype != null) {
            return ledgerformatted(source, ledgerentrytype);
        }

        transactiontype transactiontype = stobject.transactiontype(source);
        if (transactiontype != null) {
            return transactionformatted(source, transactiontype);
        }

        return source;
    }

    private static stobject transactionformatted(stobject source, transactiontype transactiontype) {
        stobject constructed = null;
        switch (transactiontype) {
            case invalid:
                break;
            case payment:
                constructed = new payment();
                break;
            case claim:
                break;
            case walletadd:
                break;
            case accountset:
                constructed = new accountset();
                break;
            case passwordfund:
                break;
            case setregularkey:
                break;
            case nicknameset:
                break;
            case offercreate:
                constructed = new offercreate();
                break;
            case offercancel:
                constructed = new offercancel();
                break;
            case contract:
                break;
            case ticketcreate:
                constructed = new ticketcreate();
                break;
            case ticketcancel:
                constructed = new ticketcancel();
                break;
            case trustset:
                constructed = new trustset();
                break;
            case enableamendment:
                break;
            case setfee:
                break;
            case addreferee:
                constructed = new addreferee();
                break;
            case dividend:
                constructed = new dividend();
                break;

        }
        if (constructed == null) {
            constructed = new transaction(transactiontype);
        }

        constructed.fields = source.fields;
        return constructed;

    }

    private static stobject ledgerformatted(stobject source, ledgerentrytype ledgerentrytype) {
        stobject constructed = null;
        switch (ledgerentrytype) {
            case offer:
                constructed = new offer();
                break;
            case ripplestate:
                constructed = new ripplestate();
                break;
            case accountroot:
                constructed = new accountroot();
                break;
            case invalid:
                break;
            case directorynode:
                constructed = new directorynode();
                break;
            case generatormap:
                break;
            case contract:
                break;
            case ledgerhashes:
                constructed = new ledgerhashes();
                break;
            case enabledamendments:
                break;
            case feesettings:
                break;
        }
        if (constructed == null) {
            constructed = new ledgerentry(ledgerentrytype);
        }
        constructed.fields = source.fields;
        return constructed;
    }
}
