package org.moorecoinlab.core.serialized.enums;

import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.ripple.bouncycastle.util.encoders.hex;

import java.util.treemap;

public enum ledgerentrytype implements serializedtype{
    invalid (-1),
    accountroot ('a'),
    directorynode('d'),
    generatormap ('g'),
    ripplestate ('r'),
    // nickname ('n'), // deprecated
    offer ('o'),
    contract ('c'),
    ledgerhashes ('h'),
    enabledamendments('f'),
    feesettings ('s'),
    ticket('t');

    final int ord;
    ledgerentrytype(int i) {
        ord = i;
    }

    static private treemap<integer, ledgerentrytype> bycode = new treemap<integer, ledgerentrytype>();
    static {
        for (object a : ledgerentrytype.values()) {
            ledgerentrytype f = (ledgerentrytype) a;
            bycode.put(f.ord, f);
        }
    }

    public static ledgerentrytype fromnumber(number i) {
        return bycode.get(i.intvalue());
    }

    public integer asinteger() {
        return ord;
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
    public static class translator extends typetranslator<ledgerentrytype> {
        @override
        public ledgerentrytype fromparser(binaryparser parser, integer hint) {
            byte[] read = parser.read(2);
            return fromnumber((read[0] << 8) | read[1]);
        }

        @override
        public ledgerentrytype frominteger(int integer) {
            return fromnumber(integer);
        }

        @override
        public ledgerentrytype fromstring(string value) {
            return ledgerentrytype.valueof(value);
        }
    }
    public static translator translate = new translator();
}
