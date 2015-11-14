package org.moorecoinlab.core.uint;

import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.ripple.bouncycastle.util.encoders.hex;

import java.math.biginteger;

abstract public class uint<subclass extends uint> extends number implements serializedtype, comparable<uint> {

    private biginteger value;

    public static biginteger max8  = new biginteger("256"),
                             max16 = new biginteger("65536"),
                             max32 = new biginteger("4294967296"),
                             max64 = new biginteger("18446744073709551616");

    public biginteger getminimumvalue() {
        return biginteger.zero;
    }
    public uint(byte[] bytes) {
        setvalue(new biginteger(1, bytes));
    }
    public uint(biginteger bi) {
        setvalue(bi);
    }
    public uint(number s) {
        setvalue(biginteger.valueof(s.longvalue()));
    }
    public uint(string s) {
        setvalue(new biginteger(s));
    }
    public uint(string s, int radix) {
        setvalue(new biginteger(s, radix));
    }


    @override
    public string tostring() {
        return value.tostring();
    }

    public uint() {}

    public abstract int getbytewidth();
    public abstract subclass instancefrom(biginteger n);

    public boolean isvalid(biginteger n) {
        return !((bitlength() / 8) > getbytewidth());
    }

    public subclass add(uint val) {
        return instancefrom(value.add(val.value));
    }

    public subclass subtract(uint val) {
        return instancefrom(value.subtract(val.value));
    }

    public subclass multiply(uint val) {
        return instancefrom(value.multiply(val.value));
    }

    public subclass divide(uint val) {
        return instancefrom(value.divide(val.value));
    }

    public subclass or(uint val) {
        return instancefrom(value.or(val.value));
    }

    public subclass shiftleft(int n) {
        return instancefrom(value.shiftleft(n));
    }

    public subclass shiftright(int n) {
        return instancefrom(value.shiftright(n));
    }

    public int bitlength() {
        return value.bitlength();
    }

    public int compareto(uint val) {
        return value.compareto(val.value);
    }

    @override
    public boolean equals(object obj) {
        if (obj instanceof uint) {
            return equals((uint) obj);
        }
        else return super.equals(obj);
    }

    public boolean equals(uint x) {
        return value.equals(x.value);
    }

    public biginteger min(biginteger val) {
        return value.min(val);
    }

    public biginteger max(biginteger val) {
        return value.max(val);
    }

    public string tostring(int radix) {
        return value.tostring(radix);
    }
    public byte[] tobytearray() {
        int length = getbytewidth();

        {
            byte[] bytes = value.tobytearray();

            if (bytes[0] == 0) {
                if (bytes.length - 1 > length) {
                    throw new illegalargumentexception("standard length exceeded for value");
                }

                byte[] tmp = new byte[length];

                system.arraycopy(bytes, 1, tmp, tmp.length - (bytes.length - 1), bytes.length - 1);

                return tmp;
            } else {
                if (bytes.length == length) {
                    return bytes;
                }

                if (bytes.length > length) {
                    throw new illegalargumentexception("standard length exceeded for value");
                }

                byte[] tmp = new byte[length];

                system.arraycopy(bytes, 0, tmp, tmp.length - bytes.length, bytes.length);

                return tmp;
            }
        }
    }

    abstract public object value();

    public biginteger biginteger(){
        return value;
    }


    @override
    public int intvalue() {
        return value.intvalue();
    }

    @override
    public long longvalue() {
        return value.longvalue();
    }

    @override
    public double doublevalue() {
        return value.doublevalue();
    }

    @override
    public float floatvalue() {
        return value.floatvalue();
    }

    @override
    public byte bytevalue() {
        return value.bytevalue();
    }

    @override
    public short shortvalue() {
        return value.shortvalue();
    }

    public void setvalue(biginteger value) {
        this.value = value;
    }

    public <t extends uint> boolean  lte(t sequence) {
        return compareto(sequence) < 1;
    }

    public boolean testbit(int f) {
        // todo, optimized ;) // move to uint32
        return value.testbit(f);
    }

    public boolean iszero() {
        return value.signum() == 0;
    }

    static public abstract class uinttranslator<t extends uint> extends typetranslator<t> {
        public abstract t newinstance(biginteger i);
        public abstract int bytewidth();

        @override
        public t fromparser(binaryparser parser, integer hint) {
            return newinstance(new biginteger(1, parser.read(bytewidth())));
        }

        @override
        public object tojson(t obj) {
            if (obj.getbytewidth() <= 4) {
                return obj.longvalue();
            } else {
                return tostring(obj);
            }
        }

        @override
        public t fromlong(long along) {
            return newinstance(biginteger.valueof(along));
        }

        @override
        public t fromstring(string value) {
            int radix = bytewidth() <= 4 ? 10 : 16;
            return newinstance(new biginteger(value, radix));
        }

        @override
        public t frominteger(int integer) {
            return fromlong(integer);
        }

        @override
        public string tostring(t obj) {
            return new string(hex.encode(obj.tobytearray()));
        }

        @override
        public void tobytessink(t obj, bytessink to) {
            to.add(obj.tobytearray());
        }
    }
}
