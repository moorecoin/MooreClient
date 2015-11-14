package org.moorecoinlab.core.types.known.tx;


import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.amount;
import org.moorecoinlab.core.stobject;
import org.moorecoinlab.core.variablelength;
import org.moorecoinlab.core.enums.transactionflag;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.formats.txformat;
import org.moorecoinlab.core.hash.halfsha512;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.prefixes.hashprefix;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.uint.uint16;
import org.moorecoinlab.core.uint.uint32;

public class transaction extends stobject {
    public static final boolean canonical_flag_deployed = true;
    public static final uint32 canonical_signature = new uint32(transactionflag.fullycanonicalsig);

    public transaction(transactiontype type) {
        setformat(txformat.formats.get(type));
        put(field.transactiontype, type);
    }

    public transactiontype transactiontype() {
        return transactiontype(this);
    }

    public hash256 signinghash() {
        halfsha512 signing = halfsha512.prefixed256(hashprefix.txsign);
        tobytessink(signing, new fieldfilter() {
            @override
            public boolean evaluate(field a) {
                return a.issigningfield();
            }
        });
        return signing.finish();
    }

    public void setcanonicalsignatureflag() {
        uint32 flags = get(uint32.flags);
        if (flags == null) {
            flags = canonical_signature;
        } else {
            flags = flags.or(canonical_signature);
        }
        put(uint32.flags, flags);
    }

    public uint32 flags() {return get(uint32.flags);}
    public uint32 sourcetag() {return get(uint32.sourcetag);}
    public uint32 sequence() {return get(uint32.sequence);}
    public uint32 lastledgersequence() {return get(uint32.lastledgersequence);}
    public uint32 operationlimit() {return get(uint32.operationlimit);}
    public hash256 previoustxnid() {return get(hash256.previoustxnid);}
    public hash256 accounttxnid() {return get(hash256.accounttxnid);}
    public amount fee() {return get(amount.fee);}
    public variablelength signingpubkey() {return get(variablelength.signingpubkey);}
    public variablelength txnsignature() {return get(variablelength.txnsignature);}
    public accountid account() {return get(accountid.account);}
    public void transactiontype(uint16 val) {put(field.transactiontype, val);}
    public void flags(uint32 val) {put(field.flags, val);}
    public void sourcetag(uint32 val) {put(field.sourcetag, val);}
    public void sequence(uint32 val) {put(field.sequence, val);}
    public void lastledgersequence(uint32 val) {put(field.lastledgersequence, val);}
    public void operationlimit(uint32 val) {put(field.operationlimit, val);}
    public void previoustxnid(hash256 val) {put(field.previoustxnid, val);}
    public void accounttxnid(hash256 val) {put(field.accounttxnid, val);}
    public void fee(amount val) {put(field.fee, val);}
    public void signingpubkey(variablelength val) {put(field.signingpubkey, val);}
    public void txnsignature(variablelength val) {put(field.txnsignature, val);}
    public void account(accountid val) {put(field.account, val);}

}
