package org.moorecoinlab.core.types.known.sle.entries;


import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.currency;
import org.moorecoinlab.core.vector256;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.hash.hash160;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.index;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.types.known.sle.ledgerentry;
import org.moorecoinlab.core.uint.uint64;

public class directorynode extends ledgerentry {
    public directorynode() {
        super(ledgerentrytype.directorynode);
    }

    public uint64 indexnext() {return get(uint64.indexnext);}
    public uint64 indexprevious() {return get(uint64.indexprevious);}
    public uint64 exchangerate() {return get(uint64.exchangerate);}
    public hash256 rootindex() {return get(hash256.rootindex);}
    public accountid owner() {return get(accountid.owner);}
    public hash160 takerpayscurrency() {return get(hash160.takerpayscurrency);}
    public hash160 takerpaysissuer() {return get(hash160.takerpaysissuer);}
    public hash160 takergetscurrency() {return get(hash160.takergetscurrency);}
    public hash160 takergetsissuer() {return get(hash160.takergetsissuer);}
    public vector256 indexes() {return get(vector256.indexes);}
    public void indexnext(uint64 val) {put(field.indexnext, val);}
    public void indexprevious(uint64 val) {put(field.indexprevious, val);}
    public void exchangerate(uint64 val) {put(field.exchangerate, val);}
    public void rootindex(hash256 val) {put(field.rootindex, val);}
    public void owner(accountid val) {put(field.owner, val);}
    public void takerpayscurrency(hash160 val) {put(field.takerpayscurrency, val);}
    public void takerpaysissuer(hash160 val) {put(field.takerpaysissuer, val);}
    public void takergetscurrency(hash160 val) {put(field.takergetscurrency, val);}
    public void takergetsissuer(hash160 val) {put(field.takergetsissuer, val);}
    public void indexes(vector256 val) {put(field.indexes, val);}

    public hash256 nextindex() {
        return index.directorynode(rootindex(), indexnext());
    }
    public hash256 previndex() {
        return index.directorynode(rootindex(), indexprevious());
    }

    public boolean haspreviousindex() {
        return indexprevious() != null;
    }

    public boolean hasnextindex() {
        return indexnext() != null;
    }

    public boolean isrootindex() {
        return rootindex().equals(index());
    }

    public void setexchangedefaults() {
        if (takergetscurrency() == null) {
            takergetscurrency(currency.vrp);
            takergetsissuer(accountid.vrp_issuer);
        } else if (takerpayscurrency() == null) {
            takerpayscurrency(currency.vrp);
            takerpaysissuer(accountid.vrp_issuer);
        }
    }

    @override
    public void setdefaults() {
        super.setdefaults();
        if (exchangerate() != null) {
            setexchangedefaults();
        }
        if (indexes() == null) {
            indexes(new vector256());
        }
    }
}
