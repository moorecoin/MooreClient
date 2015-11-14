package org.moorecoinlab.core.fields;

import java.util.*;

public enum field {
    // these are all presorted (verified in a static block below)
    // they can then be used in a treemap, using the enum (private) ordinal
    // comparator
    generic(0, type.unknown),
    invalid(-1, type.unknown),

    ledgerentrytype(1, type.uint16),
    transactiontype(2, type.uint16),

    flags(2, type.uint32),
    sourcetag(3, type.uint32),
    sequence(4, type.uint32),
    previoustxnlgrseq(5, type.uint32),
    ledgersequence(6, type.uint32),
    closetime(7, type.uint32),
    parentclosetime(8, type.uint32),
    signingtime(9, type.uint32),
    expiration(10, type.uint32),
    transferrate(11, type.uint32),
    walletsize(12, type.uint32),
    ownercount(13, type.uint32),
    destinationtag(14, type.uint32),
    highqualityin(16, type.uint32),
    highqualityout(17, type.uint32),
    lowqualityin(18, type.uint32),
    lowqualityout(19, type.uint32),
    qualityin(20, type.uint32),
    qualityout(21, type.uint32),
    stampescrow(22, type.uint32),
    bondamount(23, type.uint32),
    loadfee(24, type.uint32),
    offersequence(25, type.uint32),
    firstledgersequence(26, type.uint32), // deprecated: do not use
    // added new semantics in 9486fc416ca7c59b8930b734266eed4d5b714c50
    lastledgersequence(27, type.uint32),
    transactionindex(28, type.uint32),
    operationlimit(29, type.uint32),
    referencefeeunits(30, type.uint32),
    reservebase(31, type.uint32),
    reserveincrement(32, type.uint32),
    setflag(33, type.uint32),
    clearflag(34, type.uint32),

    indexnext(1, type.uint64),
    indexprevious(2, type.uint64),
    booknode(3, type.uint64),
    ownernode(4, type.uint64),
    basefee(5, type.uint64),
    exchangerate(6, type.uint64),
    lownode(7, type.uint64),
    highnode(8, type.uint64),
    dividendcoins(9, type.uint64),
    dividendcoinsvbc(181, type.uint64),

    emailhash(1, type.hash128),

    ledgerhash(1, type.hash256),
    parenthash(2, type.hash256),
    transactionhash(3, type.hash256),
    accounthash(4, type.hash256),
    previoustxnid(5, type.hash256),
    ledgerindex(6, type.hash256),
    walletlocator(7, type.hash256),
    rootindex(8, type.hash256),
    // added in rippled commit: 9486fc416ca7c59b8930b734266eed4d5b714c50
    accounttxnid(9, type.hash256),
    bookdirectory(16, type.hash256),
    invoiceid(17, type.hash256),
    nickname(18, type.hash256),
    amendment(19, type.hash256),
    ticketid(20, type.hash256),
    hash(257, type.hash256),
    index(258, type.hash256),

    amount(1, type.amount),
    balance(2, type.amount),
    limitamount(3, type.amount),
    takerpays(4, type.amount),
    takergets(5, type.amount),
    lowlimit(6, type.amount),
    highlimit(7, type.amount),
    fee(8, type.amount),
    sendmax(9, type.amount),
    minimumoffer(16, type.amount),
    rippleescrow(17, type.amount),
    // added in rippled commit: e7f0b8eca69dd47419eee7b82c8716b3aa5a9e39
    deliveredamount(18, type.amount),
    // these are auxillary fields
//    quality(257, type.amount),
    balancevbc(181, type.amount),
    taker_gets_funded(258, type.amount),
    taker_pays_funded(259, type.amount),

    publickey(1, type.variablelength),
    messagekey(2, type.variablelength),
    signingpubkey(3, type.variablelength),
    txnsignature(4, type.variablelength),
    generator(5, type.variablelength),
    signature(6, type.variablelength),
    domain(7, type.variablelength),
    fundcode(8, type.variablelength),
    removecode(9, type.variablelength),
    expirecode(10, type.variablelength),
    createcode(11, type.variablelength),
    memotype(12, type.variablelength),
    memodata(13, type.variablelength),
    memoformat(14, type.variablelength),

    account(1, type.accountid),
    owner(2, type.accountid),
    destination(3, type.accountid),
    issuer(4, type.accountid),
    target(7, type.accountid),
    regularkey(8, type.accountid),

    objectendmarker(1, type.stobject),
    transactionmetadata(2, type.stobject),
    creatednode(3, type.stobject),
    deletednode(4, type.stobject),
    modifiednode(5, type.stobject),
    previousfields(6, type.stobject),
    finalfields(7, type.stobject),
    newfields(8, type.stobject),
    templateentry(9, type.stobject),
    memo(10, type.stobject),

    arrayendmarker(1, type.starray),
    signingaccounts(2, type.starray),
    txnsignatures(3, type.starray),
    signatures(4, type.starray),
    template(5, type.starray),
    necessary(6, type.starray),
    sufficient(7, type.starray),
    affectednodes(8, type.starray),
    memos(9, type.starray),

    closeresolution(1, type.uint8),
    templateentrytype(2, type.uint8),
    transactionresult(3, type.uint8),

    takerpayscurrency(1, type.hash160),
    takerpaysissuer(2, type.hash160),
    takergetscurrency(3, type.hash160),
    takergetsissuer(4, type.hash160),

    paths(1, type.pathset),

    indexes(1, type.vector256),
    hashes(2, type.vector256),
    features(3, type.vector256),

    transaction(1, type.transaction),
    ledgerentry(1, type.ledgerentry),
    validation(1, type.validation);

    final int id;

    // defaults
    boolean signingfield = true;
    boolean isserialized = true;
    boolean isvlencoded = false;

    public static field fromstring(string key) {
        field f;
        try {
            f = valueof(key);
        } catch (illegalargumentexception e) {
            f = null;
        }
        return f;
    }

    public static byte[] asbytes(field field) {
        int name = field.getid(), type = field.gettype().getid();
        arraylist<byte> header = new arraylist<byte>(3);

        if (type < 16)
        {
            if (name < 16) // common type, common name
                header.add((byte)((type << 4) | name));
            else
            {
                // common type, uncommon name
                header.add((byte)(type << 4));
                header.add((byte)(name));
            }
        }
        else if (name < 16)
        {
            // uncommon type, common name
            header.add((byte)(name));
            header.add((byte)(type));
        }
        else
        {
            // uncommon type, uncommon name
            header.add((byte)(0));
            header.add((byte)(type));
            header.add((byte)(name));
        }

        byte[] headerbytes = new byte[header.size()];
        for (int i = 0; i < header.size(); i++) {
            headerbytes[i] = header.get(i);
        }

        return headerbytes;
    }

    public int getid() {
        return id;
    }

    final int code;
    final type type;
    private final byte[] bytes;
    public object tag = null;

    field(int fid, type tid) {
        id = fid;
        type = tid;
        code = (type.id << 16) | fid;
        if (isserialized()) {
            bytes = asbytes(this);
        } else {
            bytes = null;
        }
        isserialized = isserialized(this);
    }

    static private map<integer, field> bycode = new treemap<integer, field>();

    public static iterator<field> sorted(collection<field> fields) {
        arraylist<field> fieldlist = new arraylist<field>(fields);
        collections.sort(fieldlist, comparator);
        return fieldlist.iterator();
    }

    static public field fromcode(integer integer) {
        return bycode.get(integer);
    }

    public type gettype() {
        return type;
    }

    public boolean isserialized() {
        return isserialized;
    }
    public boolean isvlencoded() {
        return isvlencoded;
    }
    public boolean issigningfield() {
        return signingfield;
    }
    private static boolean isserialized(field f) {
        // this should screen out `hash` and `index` and the like
        return ((f.type.id > 0) && (f.type.id < 256) && (f.id > 0) && (f.id < 256));
    }

    static public comparator<field> comparator = new comparator<field>() {
        @override
        public int compare(field o1, field o2) {
            return o1.code - o2.code;
        }
    };

    static {
        for (field f : field.values()) {
            bycode.put(f.code, f);
            f.isserialized = isserialized(f);
            f.signingfield = f.isserialized;

            switch (f.type) {
                case variablelength:
                case accountid:
                case vector256:
                    f.isvlencoded = true;
                    break;
                default:
                    break;
            }

        }

        txnsignature.signingfield = false;

        arraylist<field> sortedfields;
        field[] values = field.values();
        sortedfields = new arraylist<field>(arrays.aslist(values));
        collections.sort(sortedfields, comparator);

        for (int i = 0; i < values.length; i++) {
            field av = values[i];
            field lv = sortedfields.get(i);
            if (av.code != lv.code) {
                throw new runtimeexception("field enum declaration isn't presorted");
            }
        }
    }

    public byte[] getbytes() {
        return bytes;
    }
}