package org.moorecoinlab.core;

import org.moorecoinlab.core.hash.hash160;
import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.uint.uint64;
import org.ripple.bouncycastle.util.encoders.hex;

import java.math.bigdecimal;
import java.math.biginteger;
import java.math.mathcontext;
import java.util.date;
import java.util.concurrent.timeunit;

/**
 * funnily enough, yes, in rippled a currency is represented by a hash160 type.
 * for the sake of consistency and convenience, this quirk is repeated here.
 *
 * https://gist.github.com/justmoon/8597643
 */
public class currency extends hash160 {
    public static final currency neutral = new currency(biginteger.one.tobytearray());
    public static final currency vrp = new currency(biginteger.zero.tobytearray());
    public static final currency vbc = new currency(hex.decode("ff"));

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

    public boolean isnative() {
        return this == currency.vrp || this == currency.vbc || equals(currency.vrp) || equals(currency.vbc);
    }

    public boolean isiou() {
        return !isnative();
    }

    public static enum type {
        hash,
        iso,      // three letter isocode
        demurrage,
        unknown;

        public static type frombyte(byte typebyte) {
            if (typebyte == 0x00) {
                return iso;
            } else if (typebyte == 0x01) {
                return demurrage;
            } else if ((typebyte & 0x80) != 0) {
                return hash;
            } else {
                return unknown;
            }
        }
    }
    type type;

    public static class demurrage {
        date intereststart;
        string isocode;
        double interestrate;

        static public bigdecimal applyrate(bigdecimal amount, bigdecimal rate, timeunit time, long units) {
            bigdecimal appliedrate = getseconds(time, units).divide(rate, mathcontext.decimal64);
            bigdecimal factor = bigdecimal.valueof(math.exp(appliedrate.doublevalue()));
            return amount.multiply(factor, mathcontext.decimal64);
        }

        static public bigdecimal calculaterate(bigdecimal rate, timeunit time, long units) {
            bigdecimal seconds = getseconds(time, units);
            bigdecimal log = ln(rate);
            return seconds.divide(log, mathcontext.decimal64);
        }

        private static bigdecimal ln(bigdecimal bd) {
            return bigdecimal.valueof(math.log(bd.doublevalue()));
        }

        private static bigdecimal getseconds(timeunit time, long units) {
            return bigdecimal.valueof(time.toseconds(units));
        }

        public demurrage(byte[] bytes) {
            binaryparser parser = new binaryparser(bytes);
            parser.skip(1); // the type
            isocode = isocodefrombytesandoffset(parser.read(3), 0);// the isocode
            intereststart = rippledate.fromparser(parser);
            long l = uint64.translate.fromparser(parser).longvalue();
            interestrate = double.longbitstodouble(l);
        }
    }
    public demurrage demurrage = null;
    public currency(byte[] bytes) {
        super(bytes);
        type = type.frombyte(this.hash[0]);
        if (type == type.demurrage) {
            demurrage = new demurrage(bytes);
        }
    }

    /**
     * it's better to extend hashtranslator than the hash160.translator directly
     * that way the generics can still vibe with the @override
     */
    public static class currencytranslator extends hashtranslator<currency> {
        @override
        public int bytewidth() {
            return 20;
        }

        @override
        public currency newinstance(byte[] b) {
            return new currency(b);
        }

        @override
        public currency fromstring(string value) {
            if (value.length() == 40 /* bytewidth() * 2 */) {
                return newinstance(hex.decode(value));
            } else if (value.equals("vrp")) {
                return vrp;
            }else if(value.equals("vbc")){
                return vbc;
            } else {
                if (!(value.length() == 3)) {
//                if (!value.matches("[a-z0-9]{3}")) {
                    throw new runtimeexception("currency code must be 3 characters");
                }
                return newinstance(encodecurrency(value));
            }
        }
    }

    public static currency fromstring(string currency) {
        return translate.fromstring(currency);
    }

    @override
    public string tostring() {
        switch (type) {
            case iso:
                string code = getcurrencycodefromtlcbytes(bytes());
                if (code.equals("vrp")) {
                    // hex of the bytes
                    return super.tostring();
                }else if(code.equals("vbc")){
                    return super.tostring();
                }else if (code.equals("\0\0\0")) {
                    if(bytes()[19] == -1 )
                        return "vbc";
                    else{
                        return "vrp";
                    }
                } else {
                    // the 3 letter isocode
                    return code;
                }
            case hash:
            case demurrage:
            case unknown:
            default:
                return super.tostring();
        }
    }

    public string humancode() {
        if (type == type.iso) {
            return getcurrencycodefromtlcbytes(hash);
        } else if (type == type.demurrage) {
            return isocodefrombytesandoffset(hash, 1);
        } else {
            throw new illegalstateexception("no human code for currency of type " + type);
        }
    }

    @override
    public boolean equals(object obj) {
        if (obj instanceof currency) {
            currency other = (currency) obj;
            byte[] bytes = this.bytes();
            byte[] otherbytes = other.bytes();

            if (type == type.iso && other.type == type.iso) {
                return (bytes[12] == otherbytes[12] &&
                        bytes[13] == otherbytes[13] &&
                        bytes[14] == otherbytes[14] &&
                        bytes[19] == otherbytes[19]);
            }
        }
        return super.equals(obj); // full comparison
    }

    public static currencytranslator translate = new currencytranslator();

    /*
    * the following are static methods, legacy from when there was no
    * usage of currency objects, just string with "vrp" ambiguity.
    * */
    public static byte[] encodecurrency(string currencycode) {
        byte[] currencybytes = new byte[20];
        currencybytes[12] = (byte) currencycode.codepointat(0);
        currencybytes[13] = (byte) currencycode.codepointat(1);
        currencybytes[14] = (byte) currencycode.codepointat(2);
        return currencybytes;
    }

    public static string getcurrencycodefromtlcbytes(byte[] bytes) {
        int i;
        boolean zeroinnoncurrencybytes = true;

        for (i = 0; i < 20; i++) {
            zeroinnoncurrencybytes = zeroinnoncurrencybytes &&
                    ((i == 12 || i == 13 || i == 14 || i == 19 ) || // currency bytes (0 or any other)
                            bytes[i] == 0);                   // non currency bytes (0)
        }

        if (zeroinnoncurrencybytes) {
            return isocodefrombytesandoffset(bytes, 12);
        } else {
            throw new illegalstateexception("currency is invalid");
        }
    }

    private static char charfrom(byte[] bytes, int i) {
        return (char) bytes[i];
    }

    private static string isocodefrombytesandoffset(byte[] bytes, int offset) {
        char a = charfrom(bytes, offset);
        char b = charfrom(bytes, offset + 1);
        char c = charfrom(bytes, offset + 2);
        return "" + a + b + c;
    }
}
