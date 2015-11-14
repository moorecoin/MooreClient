package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * der ia5string object - this is an ascii string.
 */
public class deria5string
    extends asn1primitive
    implements asn1string
{
    private byte[]  string;

    /**
     * return a ia5 string from the passed in object
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static deria5string getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof deria5string)
        {
            return (deria5string)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (deria5string)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an ia5 string from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static deria5string getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof deria5string)
        {
            return getinstance(o);
        }
        else
        {
            return new deria5string(((asn1octetstring)o).getoctets());
        }
    }

    /**
     * basic constructor - with bytes.
     */
    deria5string(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * basic constructor - without validation.
     */
    public deria5string(
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
     * contains characters that should not be in an ia5string.
     */
    public deria5string(
        string   string,
        boolean  validate)
    {
        if (string == null)
        {
            throw new nullpointerexception("string cannot be null");
        }
        if (validate && !isia5string(string))
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
        out.writeencoded(bertags.ia5_string, string);
    }

    public int hashcode()
    {
        return arrays.hashcode(string);
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof deria5string))
        {
            return false;
        }

        deria5string  s = (deria5string)o;

        return arrays.areequal(string, s.string);
    }

    /**
     * return true if the passed in string can be represented without
     * loss as an ia5string, false otherwise.
     *
     * @return true if in printable set, false otherwise.
     */
    public static boolean isia5string(
        string  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            char    ch = str.charat(i);

            if (ch > 0x007f)
            {
                return false;
            }
        }

        return true;
    }
}
