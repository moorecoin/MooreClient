package org.moorecoinlab.core.types.known.sle.entries;

import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.amount;
import org.moorecoinlab.core.variablelength;
import org.moorecoinlab.core.enums.ledgerflag;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.hash.hash128;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.types.known.sle.threadedledgerentry;
import org.moorecoinlab.core.uint.uint32;

public class accountroot extends threadedledgerentry {
    public accountroot() {
        super(ledgerentrytype.accountroot);
    }

    public uint32 sequence() {return get(uint32.sequence);}
    public uint32 transferrate() {return get(uint32.transferrate);}
    public uint32 walletsize() {return get(uint32.walletsize);}
    public uint32 ownercount() {return get(uint32.ownercount);}
    public hash128 emailhash() {return get(hash128.emailhash);}
    public hash256 walletlocator() {return get(hash256.walletlocator);}
    public amount balance() {return get(amount.balance);}
    public variablelength messagekey() {return get(variablelength.messagekey);}
    public variablelength domain() {return get(variablelength.domain);}
    public accountid account() {return get(accountid.account);}
    public accountid regularkey() {return get(accountid.regularkey);}

    public void sequence(uint32 val) {put(field.sequence, val);}
    public void transferrate(uint32 val) {put(field.transferrate, val);}
    public void walletsize(uint32 val) {put(field.walletsize, val);}
    public void ownercount(uint32 val) {put(field.ownercount, val);}
    public void emailhash(hash128 val) {put(field.emailhash, val);}
    public void walletlocator(hash256 val) {put(field.walletlocator, val);}
    public void balance(amount val) {put(field.balance, val);}
    public void messagekey(variablelength val) {put(field.messagekey, val);}
    public void domain(variablelength val) {put(field.domain, val);}
    public void account(accountid val) {put(field.account, val);}
    public void regularkey(accountid val) {put(field.regularkey, val);}

    public boolean requiresauth() {
        return flags().testbit(ledgerflag.requireauth);
    }


    @override
    public void setdefaults() {
        super.setdefaults();
        if (ownercount() == null) {
            ownercount(new uint32(0));
        }
    }
}
