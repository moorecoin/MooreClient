package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * der numericstring object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
 */
public class dernumericstring
    extends asn1primitive
    implements asn1string
{
    private byte[]  string;

    /**
     * return a numeric string from the passed in object
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static dernumericstring getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof dernumericstring)
        {
            return (dernumericstring)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (dernumericstring)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an numeric string from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static dernumericstring getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof dernumericstring)
        {
            return getinstance(o);
        }
        else
        {
            return new dernumericstring(asn1octetstring.getinstance(o).getoctets());
        }
    }

    /**
     * basic constructor - with bytes.
     */
    dernumericstring(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * basic constructor -  without validation..
     */
    public dernumericstring(
        string   string)
    {
        this(string, false);
    }

    /**
     * constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws illegalargumentexception if validate is true and the string
     * contains characters that should not be in a numericstring.
     */
    public dernumericstring(
        string   string,
        boolean  validate)
    {
        if (validate && !isnumericstring(string))
        {
            throw new illegalargumentexception("string contains illegal characters");
        }

        this.string = strings.tobytearray(string);
    }

    public string getstring()
    {
        return strings.frombytearray(string);
    }

    public string tostring()
    {
        return getstring();
    }

    public byte[] getoctets()
    {
        return arrays.clone(string);
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
    {
        return 1 + streamutil.calculatebodylength(string.length) + string.length;
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        out.writeencoded(bertags.numeric_string, string);
    }

    public int hashcode()
    {
        return arrays.hashcode(string);
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof dernumericstring))
        {
            return false;
        }

        dernumericstring  s = (dernumericstring)o;

        return arrays.areequal(string, s.string);
    }

    /**
     * return true if the string can be represented as a numericstring ('0'..'9', ' ')
     *
     * @param str string to validate.
     * @return true if numeric, fale otherwise.
     */
    public static boolean isnumericstring(
        string  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            char    ch = str.charat(i);

            if (ch > 0x007f)
            {
                return false;
            }

            if (('0' <= ch && ch <= '9') || ch == ' ')
            {
                continue;
            }

            return false;
        }

        return true;
    }
}
