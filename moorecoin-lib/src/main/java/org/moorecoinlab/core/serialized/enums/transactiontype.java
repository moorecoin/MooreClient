package org.moorecoinlab.core.serialized.enums;


import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.ripple.bouncycastle.util.encoders.hex;

import java.util.treemap;

public enum transactiontype implements serializedtype {
    invalid (-1),
    payment (0),
    claim (1), // open
    walletadd (2),
    accountset (3),
    passwordfund (4), // open
    setregularkey(5),
    nicknameset (6), // open
    offercreate (7),
    offercancel (8),
    contract (9),
    ticketcreate(10),
    ticketcancel(11),
    trustset (20),
    enableamendment(100),
    setfee(101),
    addreferee(182),
    dividend(181);

    public int asinteger() {
        return ord;
    }

    final int ord;
    transactiontype(int i) {
       ord = i;
    }

    static private treemap<integer, transactiontype> bycode = new treemap<integer, transactiontype>();
    static {
        for (object a : transactiontype.values()) {
            transactiontype f = (transactiontype) a;
            bycode.put(f.ord, f);
        }
    }

    static public transactiontype fromnumber(number i) {
        return bycode.get(i.intvalue());
    }

    // seralizedtype interface
    @override
    public byte[] tobytes() {
        return new byte[]{(byte) (ord >> 8), (byte) (ord & 0xff)};
    }
    @override
    public object tojson() {
        return tostring();
    }
    @override
    public string tohex() {
        return hex.tohexstring(tobytes());
    }
    @override
    public void tobytessink(bytessink to) {
        to.add(tobytes());
    }
    public static class translator extends typetranslator<transactiontype> {
        @override
        public transactiontype fromparser(binaryparser parser, integer hint) {
            byte[] read = parser.read(2);
            return fromnumber((read[0] << 8) | read[1]);
        }

        @override
        public transactiontype frominteger(int integer) {
            return fromnumber(integer);
        }

        @override
        public transactiontype fromstring(string value) {
            return transactiontype.valueof(value);
        }
    }
    public static translator translate = new translator();

}
