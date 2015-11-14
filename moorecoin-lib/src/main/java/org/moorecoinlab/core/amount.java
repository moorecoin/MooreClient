package org.moorecoinlab.core;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.moorecoinlab.core.uint.uint64;
import org.json.jsonexception;
import org.json.jsonobject;

import java.math.bigdecimal;
import java.math.biginteger;
import java.math.mathcontext;
import java.math.roundingmode;

/**
 * in moorecoin, amounts are either vrp/vbc, the native currency, or an iou of
 * a given currency as issued by a designated account.
 */
public class amount extends number implements serializedtype, comparable<org.moorecoinlab.core.amount>

{

    private static bigdecimal taker_pays_for_that_damn_offer = new bigdecimal("1000000000000.000100");
//    public static final amount neutral_zero = new amount(currency.neutral, accountid.neutral);

    /**
     * thrown when an amount is constructed with an invalid value
     */
    public static class precisionerror extends runtimeexception {
        public precisionerror(string s) {
            super(s);
        }
    }

    // for rounding/multiplying/dividing
    public static final mathcontext math_context = new mathcontext(16, roundingmode.half_up);
    // the maximum amount of digits in mantissa of an iou amount
    public static final int maximum_iou_precision = 16;
    // the smallest quantity of an vrp is a drop, 1 millionth of an vrp
    public static final int maximum_native_scale = 6;
    // defines bounds for native amounts
    public static final bigdecimal max_native_value = parsedecimal("100,000,000,000.0");
    public static final bigdecimal min_native_value = parsedecimal("0.000,001");

    // these are flags used when serializing to binary form
    public static final uint64 binary_flag_is_iou = new uint64("8000000000000000", 16);
    public static final uint64 binary_flag_is_non_negative_native = new uint64("4000000000000000", 16);
    public static final uint64 binary_flag_is_native_vbc = new uint64("2000000000000000", 16);

    public static final org.moorecoinlab.core.amount one_vrp = fromstring("1.0");

    // the quantity of vrp or issue(currency/issuer pairing)
    // when native, the value unit is vrp, not drops.
    private bigdecimal value;
    private currency currency;
    // if the currency is vrp
    private boolean isnative;
    // normally, in the constructor of an amount the value is checked
    // that it's scale/precision and quantity are correctly bounded.
    // if unbounded is true, these checks are skipped.
    // this is there for historical ledgers that contain amounts that
    // would now be considered malformed (in the sense of the transaction 
    // engine result class temmalformed)
    private boolean unbounded = false;
    // the zero account is used for specifying the issuer for native 
    // amounts. in practice the issuer is never used when an
    // amount is native.
    private accountid issuer;

    // while internally the value is stored as a bigdecimal
    // the mantissa and offset, as per the binary
    // format can be computed.
    // the mantissa is computed lazily, then cached
    private uint64 mantissa = null;
    // the offset is always calculated.
    private int offset;

    public amount(bigdecimal value, currency currency, accountid issuer) {
        this(value, currency, issuer, currency.isnative());
    }

    public amount(bigdecimal value) {
        isnative = true;
        currency = currency.vrp;
        this.setandcheckvalue(value);
    }

    public amount(bigdecimal value, currency currency, accountid issuer, boolean isnative, boolean unbounded) {
        this.isnative = isnative;
        this.currency = currency;
        this.unbounded = unbounded;
        this.setandcheckvalue(value);
        // done after set value which sets some default values
        this.issuer = issuer;
    }

    public amount(currency currency, accountid account) {
        this(bigdecimal.zero, currency, account);
    }

    // private constructors
    amount(bigdecimal newvalue, currency currency, accountid issuer, boolean isnative) {
        this(newvalue, currency, issuer, isnative, false);
    }

    private amount(bigdecimal value, string currency, string issuer) {
        this(value, currency);
        if (issuer != null) {
            this.issuer = accountid.fromstring(issuer);
        }
    }

    public amount(bigdecimal value, string currency) {
        this.currency = currency.fromstring(currency);
        isnative = this.currency.isnative();
        if(isnative){
            value = value.divide(new bigdecimal(1000000));
        }
        this.setandcheckvalue(value);
    }

    private void setandcheckvalue(bigdecimal value) {
        this.value = value.striptrailingzeros();
        initialize();
    }

    private void initialize() {
        if (isnative()) {
            issuer = accountid.vrp_issuer;
            if (!unbounded) {
                checkvrpbounds(value);
            }
            // offset is unused for native amounts
            offset = -6; // compared to drops.
        } else {
            if (value.precision() > maximum_iou_precision && !unbounded) {
                throw new precisionerror("overflow error!");
            }
            issuer = accountid.neutral;
            offset = calculateoffset();
        }
    }

    private org.moorecoinlab.core.amount newvalue(bigdecimal newvalue) {
        return newvalue(newvalue, false, false);
    }

    private org.moorecoinlab.core.amount newvalue(bigdecimal newvalue, boolean round, boolean unbounded) {
        if (round) {
            newvalue = roundvalue(newvalue, isnative);
        }
        return new amount(newvalue, currency, issuer, isnative, unbounded);
    }

    private org.moorecoinlab.core.amount newvalue(bigdecimal val, boolean round) {
        return newvalue(val, round, false);
    }

    /* getters and setters */

    public bigdecimal value() {
        return value;
    }

    public currency currency() {
        return currency;
    }

    public accountid issuer() {
        return issuer;
    }

    public issue issue() {
        // todo: store the currency and issuer as an issue
        return new issue(currency, issuer);
    }

    public uint64 mantissa() {
        if (mantissa == null) {
            mantissa = calculatemantissa();
        }
        return mantissa;
    }

    public int offset() {
        return offset;
    }

    public boolean isnative() {
        return isnative;
    }

    public string currencystring() {
        return currency.tostring();
    }

    public string issuerstring() {
        if (issuer == null) {
            return "";
        }
        return issuer.tostring();
    }

    /* offset & mantissa helpers */

    /**
     * @return a positive value for the mantissa
     */
    private uint64 calculatemantissa() {
        if (isnative()) {
            return new uint64(bigintegerdrops().abs());
        } else {
            return new uint64(bigintegerioumantissa());
        }
    }

    protected int calculateoffset() {
        return -maximum_iou_precision + value.precision() - value.scale();
    }

    public biginteger bigintegerioumantissa() {
        return exactbigintegerscaledbypoweroften(-offset).abs();
    }

    private biginteger bigintegerdrops() {
        return exactbigintegerscaledbypoweroften(maximum_native_scale);
    }

    private biginteger exactbigintegerscaledbypoweroften(int n) {
        return value.scalebypoweroften(n).tobigintegerexact();
    }

    /* equality testing */

    private boolean equalvalue(org.moorecoinlab.core.amount amt) {
        return compareto(amt) == 0;
    }
    @override
    public boolean equals(object obj) {
        if (obj instanceof org.moorecoinlab.core.amount) {
            return equals((org.moorecoinlab.core.amount) obj);
        }
        return super.equals(obj);
    }

    public boolean equals(org.moorecoinlab.core.amount amt) {
        return equalvalue(amt) &&
                currency.equals(amt.currency) &&
                (isnative() || issuer.equals(amt.issuer));
    }

    public boolean equalsexceptissuer(org.moorecoinlab.core.amount amt) {
        return equalvalue(amt) &&
                currencystring().equals(amt.currencystring());
    }



    public int compareto(org.moorecoinlab.core.amount amount) {
        return value.compareto(amount.value);
    }

    public boolean iszero() {
        return value.signum() == 0;
    }

    public boolean isnegative() {
        return value.signum() == -1;
    }

    // maybe you want !isnegative()
    // any amount that !isnegative() isn't necessarily positive
    // is a zero amount strictly positive? no
    public boolean ispositive() {
        return value.signum() == 1;
    }

    /**

    arithmetic operations

    there's no checking if an amount is of a different currency/issuer.
    
    all operations return amounts of the same currency/issuer as the
    first operand.

    eg.

        amountone.add(amounttwo)

        the currency/issuer of the resultant amount, is that of `amountone`
    
    divide and multiply are equivalent to the javascript moorecoin-lib
    ratio_human and product_human.

    */
    public org.moorecoinlab.core.amount add(bigdecimal augend) {
        return newvalue(value.add(augend), true);
    }

    public org.moorecoinlab.core.amount add(org.moorecoinlab.core.amount augend) {
        return add(augend.value);
    }

    public org.moorecoinlab.core.amount add(number augend) {
        return add(bigdecimal.valueof(augend.doublevalue()));
    }

    public org.moorecoinlab.core.amount subtract(bigdecimal subtrahend) {
        return newvalue(value.subtract(subtrahend), true);
    }

    public org.moorecoinlab.core.amount subtract(org.moorecoinlab.core.amount subtrahend) {
        return subtract(subtrahend.value);
    }

    public org.moorecoinlab.core.amount subtract(number subtrahend) {
        return subtract(bigdecimal.valueof(subtrahend.doublevalue()));
    }

    public org.moorecoinlab.core.amount multiply(bigdecimal divisor) {
        return newvalue(value.multiply(divisor, math_context), true);
    }

    public org.moorecoinlab.core.amount multiply(org.moorecoinlab.core.amount multiplicand) {
        return multiply(multiplicand.value);
    }

    public org.moorecoinlab.core.amount multiply(number multiplicand) {
        return multiply(bigdecimal.valueof(multiplicand.doublevalue()));
    }

    public org.moorecoinlab.core.amount divide(bigdecimal divisor) {
        return newvalue(value.divide(divisor, math_context), true);
    }

    public org.moorecoinlab.core.amount divide(org.moorecoinlab.core.amount divisor) {
        return divide(divisor.value);
    }

    public org.moorecoinlab.core.amount divide(number divisor) {
        return divide(bigdecimal.valueof(divisor.doublevalue()));
    }

    public org.moorecoinlab.core.amount negate() {
        return newvalue(value.negate());
    }

    public org.moorecoinlab.core.amount abs() {
        return newvalue(value.abs());
    }
    public org.moorecoinlab.core.amount min(org.moorecoinlab.core.amount val) {
        return (compareto(val) <= 0 ? this : val);
    }
    public org.moorecoinlab.core.amount max(org.moorecoinlab.core.amount val) {
        return (compareto(val) >= 0 ? this : val);
    }

    /* offer related helpers */
    public bigdecimal computequality(org.moorecoinlab.core.amount toexchangethiswith) {
        return value.divide(toexchangethiswith.value, mathcontext.decimal128);
    }
    /**
     * @return amount
     * the real native unit is a drop, one million of which are an vrp.
     * we want `one` unit at vrp scale (1e6 drops), or if it's an iou,
     * just `one`.
     */
    public org.moorecoinlab.core.amount one() {
        if (isnative()) {
            return one_vrp;
        } else {
            return issue().amount(1);
        }
    }

    /* serialized type implementation */

    @override
    public object tojson() {
        if (isnative()) {
            return todropsstring();
        } else {
            return tojsonobject();
        }
    }

    public jsonobject tojsonobject() {
        try {
            jsonobject out = new jsonobject();
            out.put("currency", currencystring());
            out.put("value", valuetext());
            out.put("issuer", issuerstring());
            return out;
        } catch (jsonexception e) {
            throw new runtimeexception(e);
        }
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
        uint64 man = mantissa();

        if (isnative()) {
            if (!isnegative()) {
                man = man.or(binary_flag_is_non_negative_native);
            }
            if(currency == currency.vbc || currency.vbc.equals(currency)){
                biginteger.zero.tobytearray();
                man = man.or(binary_flag_is_native_vbc);
            }
            to.add(man.tobytearray());
        } else {
            int offset = offset();
            uint64 packed;

            if (iszero()) {
                packed = binary_flag_is_iou;
            } else if (isnegative()) {
                packed = man.or(new uint64(512 + 0 + 97 + offset).shiftleft(64 - 10));
            } else {
                packed = man.or(new uint64(512 + 256 + 97 + offset).shiftleft(64 - 10));
            }

            to.add(packed.tobytearray());
            to.add(currency.bytes());
            to.add(issuer.bytes());
        }
    }

    public static class translator extends typetranslator<org.moorecoinlab.core.amount> {
        @override
        public org.moorecoinlab.core.amount fromstring(string s) {
            return org.moorecoinlab.core.amount.fromstring(s);
        }

        @override
        public org.moorecoinlab.core.amount fromparser(binaryparser parser, integer hint) {
            bigdecimal value;
            byte[] mantissa = parser.read(8);
            byte b1 = mantissa[0], b2 = mantissa[1];

            boolean isiou = (b1 & 0x80) != 0;
            boolean ispositive = (b1 & 0x40) != 0;
            int sign = ispositive ? 1 : -1;

            if (isiou) {
                mantissa[0] = 0;
                currency curr = currency.translate.fromparser(parser);
                accountid issuer = accountid.translate.fromparser(parser);
                int offset = ((b1 & 0x3f) << 2) + ((b2 & 0xff) >> 6) - 97;
                mantissa[1] &= 0x3f;

                value = new bigdecimal(new biginteger(sign, mantissa), -offset);
                return new amount(value, curr, issuer, false);
            } else {
                mantissa[0] &= 0x3f;
                value = xrpfromdropsmantissa(mantissa, sign);
                return new amount(value);
            }
        }

        @override
        public string tostring(org.moorecoinlab.core.amount obj) {
            return obj.stringrepr();
        }

        @override
        public jsonobject tojsonobject(org.moorecoinlab.core.amount obj) {
            return obj.tojsonobject();
        }

        @override
        public org.moorecoinlab.core.amount fromjsonobject(jsonobject jsonobject) {
            try {
                string valuestring = jsonobject.getstring("value");
                string issuerstring = jsonobject.getstring("issuer");
                string currencystring = jsonobject.getstring("currency");
                return new amount(new bigdecimal(valuestring), currencystring, issuerstring);
            } catch (jsonexception e) {
                throw new runtimeexception(e);
            }
        }
    }
    static public translator translate = new translator();

    public static bigdecimal xrpfromdropsmantissa(byte[] mantissa, int sign) {
        return new bigdecimal(new biginteger(sign, mantissa), 6);
    }

    /* number overides */
    @override
    public int intvalue() {
        return value.intvalueexact();
    }

    @override
    public long longvalue() {
        return value.longvalueexact();
    }

    @override
    public float floatvalue() {
        return value.floatvalue();
    }

    @override
    public double doublevalue() {
        return value.doublevalue();
    }

    public biginteger bigintegervalue() {
        return value.tobigintegerexact();
    }

    public org.moorecoinlab.core.amount newissuer(accountid issuer) {
        return new amount(value, currency, issuer);
    }

    // static constructors
    public static org.moorecoinlab.core.amount fromstring(string val) {
        if (val.contains("/")) {
            return fromioustring(val);
        } else if (val.contains(".")) {
            return fromxrpstring(val);
        } else {
            return fromdropstring(val);
        }
    }

    public static org.moorecoinlab.core.amount fromdropstring(string val) {
        bigdecimal drops = new bigdecimal(val).scalebypoweroften(-6);
        checkdropsvaluewhole(val);
        return new amount(drops);
    }

    public static org.moorecoinlab.core.amount fromioustring(string val) {
        string[] split = val.split("/");
        if (split.length == 1) {
            throw new runtimeexception("iou string must be in the form number/currencystring or number/currencystring/issuerstring");
        } else if (split.length == 2) {
            return new amount(new bigdecimal(split[0]), split[1]);
        } else {
            return new amount(new bigdecimal(split[0]), split[1], split[2]);
        }
    }

    @deprecated
    private static org.moorecoinlab.core.amount fromxrpstring(string valuestring) {
        bigdecimal val = new bigdecimal(valuestring);
        return new amount(val);
    }

    /**
     * @return a string representation as used by moorecoin json format
     */
    public string stringrepr() {
        if (isnative()) {
            return todropsstring();
        } else {
            return ioutextfull();
        }
    }

    public string todropsstring() {
        if (!isnative()) {
            throw new runtimeexception("amount is not native");
        }
        return bigintegerdrops().tostring();
    }

    private string ioutext() {
        return string.format("%s/%s", valuetext(), currencystring());
    }

    public string ioutextfull() {
        return string.format("%s/%s/%s", valuetext(), currencystring(), issuerstring());
    }

    public string totextfull() {
        if (isnative()) {
            return nativetext();
        } else {
            return ioutextfull();
        }
    }

    public string nativetext() {
        return string.format("%s/vrp", valuetext());
    }

    @override
    public string tostring() {
        return totextfull();
    }

    public string totext() {
        if (isnative()) {
            return nativetext();
        } else {
            return ioutext();
        }
    }

    /**
     * @return a string containing the value as a decimal number (in vrp scale)
     */
    public string valuetext() {
        return value.signum() == 0 ? "0" : value().toplainstring();
    }

    public static void checklowerdropbound(bigdecimal val) {
        if (val.scale() > 6) {
            throw getoutofboundserror(val, "bigger", min_native_value);
        }
    }

    public static void checkupperbound(bigdecimal val) {
        if (val.compareto(max_native_value) == 1) {
            throw getoutofboundserror(val, "bigger", max_native_value);
        }
    }

    private static precisionerror getoutofboundserror(bigdecimal abs, string sized, bigdecimal bound) {
        return new precisionerror(abs.toplainstring() + " is " + sized + " than bound " + bound);
    }

    public static void checkvrpbounds(bigdecimal value) {
        // this is for that damn offer at index: 6310d78e6ad408892743dd62455694162e758da283d0e4a2cb3a3c173b7c794a
        if (value.compareto(taker_pays_for_that_damn_offer) == 0) {
            return;
        }
        value = value.abs();
        checklowerdropbound(value);
        checkupperbound(value);
    }

    public static void checkdropsvaluewhole(string drops) {
        boolean contains = drops.contains(".");
        if (contains) {
            throw new runtimeexception("drops string contains floating point is decimal");
        }
    }

    public static bigdecimal roundvalue(bigdecimal value, boolean nativesrc) {
        int i = value.precision() - value.scale();
        return value.setscale(nativesrc ? maximum_native_scale :
                maximum_iou_precision - i,
                math_context.getroundingmode());
    }

    private static bigdecimal parsedecimal(string s) {
        return new bigdecimal(s.replace(",", "")); //# .scalebypoweroften(6);
    }

    public static typedfields.amountfield amountfield(final field f) {
        return new typedfields.amountfield() {
            @override
            public field getfield() {
                return f;
            }
        };
    }

    static public typedfields.amountfield amount = amountfield(field.amount);
    static public typedfields.amountfield balance = amountfield(field.balance);
    static public typedfields.amountfield limitamount = amountfield(field.limitamount);
    static public typedfields.amountfield deliveredamount = amountfield(field.deliveredamount);
    static public typedfields.amountfield takerpays = amountfield(field.takerpays);
    static public typedfields.amountfield takergets = amountfield(field.takergets);
    static public typedfields.amountfield lowlimit = amountfield(field.lowlimit);
    static public typedfields.amountfield highlimit = amountfield(field.highlimit);
    static public typedfields.amountfield fee = amountfield(field.fee);
    static public typedfields.amountfield sendmax = amountfield(field.sendmax);
    static public typedfields.amountfield minimumoffer = amountfield(field.minimumoffer);
    static public typedfields.amountfield rippleescrow = amountfield(field.rippleescrow);
    static public typedfields.amountfield taker_gets_funded = amountfield(field.taker_gets_funded);
    static public typedfields.amountfield taker_pays_funded = amountfield(field.taker_pays_funded);

}
