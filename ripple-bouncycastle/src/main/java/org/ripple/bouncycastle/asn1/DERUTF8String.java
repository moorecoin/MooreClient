package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * der utf8string object.
 */
public class derutf8string
    extends asn1primitive
    implements asn1string
{
    private byte[]  string;

    /**
     * return an utf8 string from the passed in object.
     * 
     * @exception illegalargumentexception
     *                if the object cannot be converted.
     */
    public static derutf8string getinstance(object obj)
    {
        if (obj == null || obj instanceof derutf8string)
        {
            return (derutf8string)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (derutf8string)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: "
                + obj.getclass().getname());
    }

    /**
     * return an utf8 string from a tagged object.
     * 
     * @param obj
     *            the tagged object holding the object we want
     * @param explicit
     *            true if the object is meant to be explicitly tagged false
     *            otherwise.
     * @exception illegalargumentexception
     *                if the tagged object cannot be converted.
     */
    public static derutf8string getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof derutf8string)
        {
            return getinstance(o);
        }
        else
        {
            return new derutf8string(asn1octetstring.getinstance(o).getoctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     */
    derutf8string(byte[] string)
    {
        this.string = string;
    }

    /**
     * basic constructor
     */
    public derutf8string(string string)
    {
        this.string = strings.toutf8bytearray(string);
    }

    public string getstring()
    {
        return strings.fromutf8bytearray(string);
    }

    public string tostring()
    {
        return getstring();
    }

    public int hashcode()
    {
        return arrays.hashcode(string);
    }

    boolean asn1equals(asn1primitive o)
    {
        if (!(o instanceof derutf8string))
        {
            return false;
        }

        derutf8string s = (derutf8string)o;

        return arrays.areequal(string, s.string);
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
        throws ioexception
    {
        return 1 + streamutil.calculatebodylength(string.length) + string.length;
    }

    void encode(asn1outputstream out)
        throws ioexception
    {
        out.writeencoded(bertags.utf8_string, string);
    }
}
