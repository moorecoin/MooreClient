package org.moorecoinlab.core.serialized;

import org.json.jsonarray;
import org.json.jsonobject;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * @param <t> the serializedtype class
 * todo, this should only really have methods that each class over-rides
 *       it's currently pretty nasty
 */
public abstract class typetranslator<t extends serializedtype> {

    @suppresswarnings("unchecked")
    public t fromvalue(object object) {
        switch (value.typeof(object)) {
            case string:
                return fromstring((string) object);
            case double:
                return fromdouble((double) object);
            case integer:
                return frominteger((integer) object);
            case long:
                return fromlong((long) object);
            case boolean:
                return fromboolean((boolean) object);
            case json_array:
                return fromjsonarray((jsonarray) object);
            case json_object:
                return fromjsonobject((jsonobject) object);
            case unknown:
            default:
                return (t) object;
        }
    }

    public boolean toboolean(t obj) {
        throw new unsupportedoperationexception();
    }

    public long tolong(t obj) {
        throw new unsupportedoperationexception();
    }

    public int tointeger(t obj) {
        throw new unsupportedoperationexception();
    }

    public double todouble(t obj) {
        throw new unsupportedoperationexception();
    }

    public string tostring(t obj) {
        return obj.tostring();
    }

    public t fromjsonobject(jsonobject jsonobject) {
        throw new unsupportedoperationexception();
    }

    public t fromjsonarray(jsonarray jsonarray) {
        throw new unsupportedoperationexception();
    }

    public t fromboolean(boolean aboolean) {
        throw new unsupportedoperationexception();
    }

    public t fromlong(long along) {
        throw new unsupportedoperationexception();
    }

    public t frominteger(int integer) {
        throw new unsupportedoperationexception();
    }

    public t fromdouble(double adouble) {
        throw new unsupportedoperationexception();
    }

    public t fromstring(string value) {
        throw new unsupportedoperationexception();
    }

    /**
     * @param hint using a boxed integer, allowing null for no hint
     *             this generic parameter can be used to hint the amount of
     *             bytes (vl) (or for any other purpose desired)
     */
    public abstract t fromparser(binaryparser parser, integer hint);

    public t fromparser(binaryparser parser) {
        return fromparser(parser, null);
    }

    public t frombytes(byte[] b) {
        return fromparser(new binaryparser(b));
    }

    public t fromhex(string hex) {
        return frombytes(hex.decode(hex));
    }

    public jsonobject tojsonobject(t obj) {
        throw new unsupportedoperationexception();
    }

    public jsonarray tojsonarray(t obj) {
        throw new unsupportedoperationexception();
    }
    public object tojson(t obj) {
        return obj.tojson();
    }

    public void tobytessink(t obj, bytessink to) {
        obj.tobytessink(to);
    }

    public byte[] tobytes(t obj) {
        byteslist to = new byteslist();
        tobytessink(obj, to);
        return to.bytes();
    }

    public string tohex(t obj) {
        byteslist to = new byteslist();
        tobytessink(obj, to);
        return to.byteshex();
    }
}
