package org.moorecoinlab.core.uint;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.typetranslator;

import java.math.biginteger;

public class uint32 extends uint<uint32> {
    public static typetranslator<uint32> translate = new uinttranslator<uint32>() {
        @override
        public uint32 newinstance(biginteger i) {
            return new uint32(i);
        }

        @override
        public int bytewidth() {
            return 4;
        }
    };

    public uint32(byte[] bytes) {
        super(bytes);
    }

    public uint32(biginteger value) {
        super(value);
    }

    public uint32(number s) {
        super(s);
    }
    public uint32(string s) {
        super(s);
    }

    public uint32(string s, int radix) {
        super(s, radix);
    }

    @override
    public int getbytewidth() {
        return 4;
    }

    @override
    public uint32 instancefrom(biginteger n) {
        return new uint32(n);
    }

    @override
    public long value() {
        return longvalue();
    }

    private uint32(){}

    private static typedfields.uint32field int32field(final field f) {
        return new typedfields.uint32field(){ @override public field getfield() {return f;}};
    }

    static public typedfields.uint32field flags = int32field(field.flags);
    static public typedfields.uint32field sourcetag = int32field(field.sourcetag);
    static public typedfields.uint32field sequence = int32field(field.sequence);
    static public typedfields.uint32field previoustxnlgrseq = int32field(field.previoustxnlgrseq);
    static public typedfields.uint32field ledgersequence = int32field(field.ledgersequence);
    static public typedfields.uint32field closetime = int32field(field.closetime);
    static public typedfields.uint32field parentclosetime = int32field(field.parentclosetime);
    static public typedfields.uint32field signingtime = int32field(field.signingtime);
    static public typedfields.uint32field expiration = int32field(field.expiration);
    static public typedfields.uint32field transferrate = int32field(field.transferrate);
    static public typedfields.uint32field walletsize = int32field(field.walletsize);
    static public typedfields.uint32field ownercount = int32field(field.ownercount);
    static public typedfields.uint32field destinationtag = int32field(field.destinationtag);
    static public typedfields.uint32field highqualityin = int32field(field.highqualityin);
    static public typedfields.uint32field highqualityout = int32field(field.highqualityout);
    static public typedfields.uint32field lowqualityin = int32field(field.lowqualityin);
    static public typedfields.uint32field lowqualityout = int32field(field.lowqualityout);
    static public typedfields.uint32field qualityin = int32field(field.qualityin);
    static public typedfields.uint32field qualityout = int32field(field.qualityout);
    static public typedfields.uint32field stampescrow = int32field(field.stampescrow);
    static public typedfields.uint32field bondamount = int32field(field.bondamount);
    static public typedfields.uint32field loadfee = int32field(field.loadfee);
    static public typedfields.uint32field offersequence = int32field(field.offersequence);
    static public typedfields.uint32field firstledgersequence = int32field(field.firstledgersequence);
    static public typedfields.uint32field lastledgersequence = int32field(field.lastledgersequence);
    static public typedfields.uint32field transactionindex = int32field(field.transactionindex);
    static public typedfields.uint32field operationlimit = int32field(field.operationlimit);
    static public typedfields.uint32field referencefeeunits = int32field(field.referencefeeunits);
    static public typedfields.uint32field reservebase = int32field(field.reservebase);
    static public typedfields.uint32field reserveincrement = int32field(field.reserveincrement);
    static public typedfields.uint32field setflag = int32field(field.setflag);
    static public typedfields.uint32field clearflag = int32field(field.clearflag);

    @override
    public object tojson() {
        return translate.tojson(this);
    }

    @override
    public byte[] tobytes() {
        return translate.tobytes(this);
    }

    @override
    public string tohex() {
        return translate.tohex(this);
    }

    @override
    public void tobytessink(bytessink to) {
        translate.tobytessink(this, to);
    }
}
