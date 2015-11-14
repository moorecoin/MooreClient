package org.moorecoinlab.core.types.known.sle.entries;


import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.amount;
import org.moorecoinlab.core.currency;
import org.moorecoinlab.core.issue;
import org.moorecoinlab.core.enums.ledgerflag;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.index;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.types.known.sle.threadedledgerentry;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.core.uint.uint64;

import java.util.arrays;
import java.util.list;

public class ripplestate extends threadedledgerentry {
    public ripplestate() {
        super(ledgerentrytype.ripplestate);
    }

    public uint32 highqualityin() {return get(uint32.highqualityin);}
    public uint32 highqualityout() {return get(uint32.highqualityout);}
    public uint32 lowqualityin() {return get(uint32.lowqualityin);}
    public uint32 lowqualityout() {return get(uint32.lowqualityout);}
    public uint64 lownode() {return get(uint64.lownode);}
    public uint64 highnode() {return get(uint64.highnode);}
    public amount balance() {return get(amount.balance);}
    public amount lowlimit() {return get(amount.lowlimit);}
    public amount highlimit() {return get(amount.highlimit);}
    public void highqualityin(uint32 val) {put(field.highqualityin, val);}
    public void highqualityout(uint32 val) {put(field.highqualityout, val);}
    public void lowqualityin(uint32 val) {put(field.lowqualityin, val);}
    public void lowqualityout(uint32 val) {put(field.lowqualityout, val);}
    public void lownode(uint64 val) {put(field.lownode, val);}
    public void highnode(uint64 val) {put(field.highnode, val);}
    public void balance(amount val) {put(field.balance, val);}
    public void lowlimit(amount val) {put(field.lowlimit, val);}
    public void highlimit(amount val) {put(field.highlimit, val);}


    public accountid lowaccount() {
        return lowlimit().issuer();
    }

    public accountid highaccount() {
        return highlimit().issuer();
    }

    public list<accountid> sortedaccounts() {
        return arrays.aslist(lowaccount(), highaccount());
    }

    public typedfields.amountfield limitfieldfor(accountid source) {
        if (lowaccount().equals(source)) {
            return amount.lowlimit;
        }
        if (highaccount().equals(source)) {
            return amount.highlimit;
        } else {
            return null;
        }
    }

    public boolean isfor(accountid source) {
        return lowaccount().equals(source) || highaccount().equals(source);
    }

    public boolean isfor(issue issue) {
        return isfor(issue.issuer()) && balance().currency().equals(issue.currency());
    }

    // todo, can optimize this
    public boolean isfor(accountid s1, accountid s2, currency currency) {
        return currency.equals(balance().currency()) && isfor(s1) && isfor(s2);
    }

    public currency currency() {
        return balance().currency();
    }

    public amount balancefor(accountid owner) {
        typedfields.amountfield field = limitfieldfor(owner);
        amount balance = balance();
        accountid issuer = lowaccount();
        if (field == amount.highlimit) {
            balance = balance.negate();
            issuer = highaccount();
        }
        return balance.newissuer(issuer);
    }

    public amount issued() {
        amount balance = balance();
        if (balance.isnegative()) {
            // balance is in terms of the lowaccount, so if the
            // balance is negative, that means it has issued
            return balance.negate().newissuer(lowaccount());
        } else {
            // if it's positive, then the lowaccount has money
            // issued by the highaccount
            return balance.newissuer(highaccount());
        }
    }

    @deprecated() // "not deprecated but needs fixing"
    public boolean authorizedby(accountid account) {
        uint32 flags = flags();
        return flags == null || flags.testbit(ishighaccount(account) ? ledgerflag.highauth : ledgerflag.lowauth);
    }

    private boolean isbitset(int flags, int flag) {
        return (flags & flag) != 0;
    }

    private boolean ishighaccount(accountid account) {
        return highaccount().equals(account);
    }
    private boolean islowaccount(accountid account) {
        return lowaccount().equals(account);
    }


    public hash256 lownodeownerdirectory() {
        hash256 ownerdir = index.ownerdirectory(lowaccount());
        return index.directorynode(ownerdir, lownode());
    }
    public hash256 highnodeownerdirectory() {
        hash256 ownerdir = index.ownerdirectory(highaccount());
        return index.directorynode(ownerdir, highnode());
    }

    public hash256[] directoryindexes() {
        return new hash256[]{lownodeownerdirectory(), highnodeownerdirectory()};
    }

    @override
    public void setdefaults() {
        super.setdefaults();

        if (lownode() == null) {
            lownode(new uint64(0));
        }
        if (highnode() == null) {
            highnode(new uint64(0));
        }
    }
}
