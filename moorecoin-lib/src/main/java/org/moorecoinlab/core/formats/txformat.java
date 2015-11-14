package org.moorecoinlab.core.formats;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.serialized.enums.transactiontype;

import java.util.enummap;

public class txformat extends format {
    static public enummap<transactiontype, txformat> formats = new enummap<transactiontype, txformat>(transactiontype.class);
    public final transactiontype transactiontype;

    static public txformat fromstring(string name) {
        return gettxformat(transactiontype.valueof(name));
    }

    static public txformat fromnumber(number ord) {
        return gettxformat(transactiontype.fromnumber(ord));
    }

    static public txformat fromvalue(object o) {
        if (o instanceof number) {
            return fromnumber(((number) o).intvalue());
        } else if (o instanceof string){
            return fromstring((string) o);
        }
        else {
            return null;
        }
    }

    private static txformat gettxformat(transactiontype key) {
        if (key == null) return null;
        return formats.get(key);
    }

    public txformat(transactiontype type, object... args) {
        super(args);
        transactiontype = type;
        addcommonfields();
        formats.put(transactiontype, this);
    }

    @override
    public void addcommonfields() {
        put(field.transactiontype,     requirement.required);
        put(field.account,             requirement.required);
        put(field.sequence,            requirement.required);
        put(field.fee,                 requirement.required);
        put(field.signingpubkey,       requirement.required);

        put(field.flags,               requirement.optional);
        put(field.sourcetag,           requirement.optional);
        put(field.previoustxnid,       requirement.optional);
        put(field.operationlimit,      requirement.optional);
        put(field.txnsignature,        requirement.optional);
        put(field.accounttxnid,        requirement.optional);
        put(field.lastledgersequence,  requirement.optional);
    }

    static public txformat accountset = new txformat(
            transactiontype.accountset,
            field.emailhash,       requirement.optional,
            field.walletlocator,   requirement.optional,
            field.walletsize,      requirement.optional,
            field.messagekey,      requirement.optional,
            field.domain,          requirement.optional,
            field.transferrate,    requirement.optional,
            field.setflag,         requirement.optional,
            field.clearflag,       requirement.optional);

    static public txformat trustset = new txformat(
            transactiontype.trustset,
            field.limitamount,     requirement.optional,
            field.qualityin,       requirement.optional,
            field.qualityout,      requirement.optional);

    static public txformat offercreate = new txformat(
            transactiontype.offercreate,
            field.takerpays,       requirement.required,
            field.takergets,       requirement.required,
            field.expiration,      requirement.optional,
            field.offersequence,   requirement.optional);

    static public txformat offercancel = new txformat(
            transactiontype.offercancel,
            field.offersequence,   requirement.required);

    static public txformat ticketcreate = new txformat(
            transactiontype.ticketcreate,
            field.target,     requirement.optional,
            field.expiration, requirement.optional);

    static public txformat ticketcancel = new txformat(
            transactiontype.ticketcancel,
            field.ticketid,   requirement.required);

    static public txformat setregularkey = new txformat(
            transactiontype.setregularkey,
            field.regularkey,  requirement.optional);

    static public txformat payment = new txformat(
            transactiontype.payment,
            field.destination,     requirement.required,
            field.amount,          requirement.required,
            field.sendmax,         requirement.optional,
            field.paths,           requirement.default,
            field.invoiceid,       requirement.optional,
            field.destinationtag,  requirement.optional);

    static public txformat contract = new txformat(
            transactiontype.contract,
            field.expiration,      requirement.required,
            field.bondamount,      requirement.required,
            field.stampescrow,     requirement.required,
            field.rippleescrow,    requirement.required,
            field.createcode,      requirement.optional,
            field.fundcode,        requirement.optional,
            field.removecode,      requirement.optional,
            field.expirecode,      requirement.optional);

    static public txformat amendment = new txformat(
            transactiontype.enableamendment,
            field.amendment,         requirement.required);

    static public txformat setfee = new txformat(
            transactiontype.setfee,
            field.basefee,             requirement.required,
            field.referencefeeunits,   requirement.required,
            field.reservebase,         requirement.required,
            field.reserveincrement,    requirement.required);
}
