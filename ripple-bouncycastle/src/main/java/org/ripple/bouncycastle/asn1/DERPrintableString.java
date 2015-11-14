package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * der printablestring object.
 */
public class derprintablestring
    extends asn1primitive
    implements asn1string
{
    private byte[]  string;

    /**
     * return a printable string from the passed in object.
     * 
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static derprintablestring getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof derprintablestring)
        {
            return (derprintablestring)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (derprintablestring)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return a printable string from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static derprintablestring getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof derprintablestring)
        {
            return getinstance(o);
        }
        else
        {
            return new derprintablestring(asn1octetstring.getinstance(o).getoctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     */
    derprintablestring(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * basic constructor - this does not validate the string
     */
    public derprintablestring(
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
     * contains characters that should not be in a printablestring.
     */
    public derprintablestring(
        string   string,
        boolean  validate)
    {
        if (validate && !isprintablestring(string))
        {
            throw new illegalargumentexception("string contains illegal characters");
        }

        this.string = strings.tobytearray(string);
    }

    public string getstring()
    {
        return strings.frombytearray(string);
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
        out.writeencoded(bertags.printable_string, string);
    }

    public int hashcode()
    {
        return arrays.hashcode(string);
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof derprintablestring))
        {
            return false;
        }

        derprintablestring  s = (derprintablestring)o;

        return arrays.areequal(string, s.string);
    }

    public string tostring()
    {
        return getstring();
    }

    /**
     * return true if the passed in string can be represented without
     * loss as a printablestring, false otherwise.
     *
     * @return true if in printable set, false otherwise.
     */
    public static boolean isprintablestring(
        string  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            char    ch = str.charat(i);

            if (ch > 0x007f)
            {
                return false;
            }

            if ('a' <= ch && ch <= 'z')
            {
                continue;
            }

            if ('a' <= ch && ch <= 'z')
            {
                continue;
            }

            if ('0' <= ch && ch <= '9')
            {
                continue;
            }

            switch (ch)
            {
            case ' ':
            case '\'':
            case '(':
            case ')':
            case '+':
            case '-':
            case '.':
            case ':':
            case '=':
            case '?':
            case '/':
            case ',':
                continue;
            }

            return false;
        }

        return true;
    }
}
