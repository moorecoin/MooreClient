package org.moorecoinlab.core.formats;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;

import java.util.enummap;

public class leformat extends format {
    static public enummap<ledgerentrytype, leformat> formats = new enummap<ledgerentrytype, leformat>(ledgerentrytype.class);

    static public leformat fromstring(string name) {
        return getledgerformat(ledgerentrytype.valueof(name));
    }

    static public leformat fromnumber(number ord) {
        return getledgerformat(ledgerentrytype.fromnumber(ord));
    }

    static public leformat fromvalue(object o) {
        if (o instanceof number) {
            return fromnumber(((number) o).intvalue());
        } else if (o instanceof string){
            return fromstring((string) o);
        }
        else {
            return null;
        }
    }

    public static leformat getledgerformat(ledgerentrytype key) {
        if (key == null) return null;
        return formats.get(key);
    }

    public final ledgerentrytype ledgerentrytype;

    public leformat(ledgerentrytype type, object... args) {
        super(args);
        ledgerentrytype = type;
        addcommonfields();
        formats.put(type, this);
    }

    @override
    public void addcommonfields() {
        put(field.ledgerindex,             requirement.optional);
        put(field.ledgerentrytype,         requirement.required);
        put(field.flags,                   requirement.required);
    }

    public static leformat accountroot = new leformat(
            ledgerentrytype.accountroot,
            field.account,             requirement.required,
            field.sequence,            requirement.required,
            field.balance,             requirement.required,
            field.ownercount,          requirement.required,
            field.previoustxnid,       requirement.required,
            field.previoustxnlgrseq,   requirement.required,
            field.regularkey,          requirement.optional,
            field.emailhash,           requirement.optional,
            field.walletlocator,       requirement.optional,
            field.walletsize,          requirement.optional,
            field.messagekey,          requirement.optional,
            field.transferrate,        requirement.optional,
            field.domain,              requirement.optional
    );

    public static leformat contract = new leformat(
            ledgerentrytype.contract,
            field.account,             requirement.required,
            field.balance,             requirement.required,
            field.previoustxnid,       requirement.required,
            field.previoustxnlgrseq,   requirement.required,
            field.issuer,              requirement.required,
            field.owner,               requirement.required,
            field.expiration,          requirement.required,
            field.bondamount,          requirement.required,
            field.createcode,          requirement.optional,
            field.fundcode,            requirement.optional,
            field.removecode,          requirement.optional,
            field.expirecode,          requirement.optional
    );

    public static leformat directorynode = new leformat(
            ledgerentrytype.directorynode,
            field.owner,               requirement.optional,  // for owner directories
            field.takerpayscurrency,   requirement.optional,  // for order book directories
            field.takerpaysissuer,     requirement.optional,  // for order book directories
            field.takergetscurrency,   requirement.optional,  // for order book directories
            field.takergetsissuer,     requirement.optional,  // for order book directories
            field.exchangerate,        requirement.optional,  // for order book directories
            field.indexes,             requirement.required,
            field.rootindex,           requirement.required,
            field.indexnext,           requirement.optional,
            field.indexprevious,       requirement.optional
    );

    public static leformat generatormap = new leformat(
            ledgerentrytype.generatormap,
            field.generator,           requirement.required
    );

    public static leformat offer = new leformat(
            ledgerentrytype.offer,
            field.account,             requirement.required,
            field.sequence,            requirement.required,
            field.takerpays,           requirement.required,
            field.takergets,           requirement.required,
            field.bookdirectory,       requirement.required,
            field.booknode,            requirement.required,
            field.ownernode,           requirement.required,
            field.previoustxnid,       requirement.required,
            field.previoustxnlgrseq,   requirement.required,
            field.expiration,          requirement.optional
    );

    public static leformat ticket = new leformat(
            ledgerentrytype.ticket,
            field.previoustxnid,       requirement.required,
            field.previoustxnlgrseq,   requirement.required,
            field.account,             requirement.required,
            field.sequence,            requirement.required,
            field.ownernode,           requirement.required,
            field.target,              requirement.optional,
            field.expiration,          requirement.optional
    );

    public static leformat ripplestate = new leformat(
            ledgerentrytype.ripplestate,
            field.balance,             requirement.required,
            field.lowlimit,            requirement.required,
            field.highlimit,           requirement.required,
            field.previoustxnid,       requirement.required,
            field.previoustxnlgrseq,   requirement.required,
            field.lownode,             requirement.optional,
            field.lowqualityin,        requirement.optional,
            field.lowqualityout,       requirement.optional,
            field.highnode,            requirement.optional,
            field.highqualityin,       requirement.optional,
            field.highqualityout,      requirement.optional
    );

    public static leformat ledgerhashes = new leformat(
            ledgerentrytype.ledgerhashes,
            field.firstledgersequence, requirement.optional, // remove if we do a ledger restart
            field.lastledgersequence,  requirement.optional,
            field.hashes,              requirement.required
    );

    public static leformat enabledamendments = new leformat(
            ledgerentrytype.enabledamendments,
            field.features, requirement.required
    );

    public static leformat feesettings = new leformat(
            ledgerentrytype.feesettings,
            field.basefee,             requirement.required,
            field.referencefeeunits,   requirement.required,
            field.reservebase,         requirement.required,
            field.reserveincrement,    requirement.required
    );
}
