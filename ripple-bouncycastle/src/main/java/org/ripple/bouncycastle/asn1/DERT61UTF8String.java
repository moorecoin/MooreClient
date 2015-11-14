package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * der t61string (also the teletex string) - a "modern" encapsulation that uses utf-8. if at all possible, avoid this one! it's only for emergencies.
 * use utf8string instead.
 */
public class dert61utf8string
    extends asn1primitive
    implements asn1string
{
    private byte[] string;

    /**
     * return a t61 string from the passed in object. utf-8 encoding is assumed in this case.
     *
     * @throws illegalargumentexception if the object cannot be converted.
     */
    public static dert61utf8string getinstance(
        object obj)
    {
        if (obj instanceof dert61string)
        {
            return new dert61utf8string(((dert61string)obj).getoctets());
        }

        if (obj == null || obj instanceof dert61utf8string)
        {
            return (dert61utf8string)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return new dert61utf8string(((dert61string)frombytearray((byte[])obj)).getoctets());
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an t61 string from a tagged object. utf-8 encoding is assumed in this case.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws illegalargumentexception if the tagged object cannot
     * be converted.
     */
    public static dert61utf8string getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof dert61string || o instanceof dert61utf8string)
        {
            return getinstance(o);
        }
        else
        {
            return new dert61utf8string(asn1octetstring.getinstance(o).getoctets());
        }
    }

    /**
     * basic constructor - string encoded as a sequence of bytes.
     */
    public dert61utf8string(
        byte[] string)
    {
        this.string = string;
    }

    /**
     * basic constructor - with string utf8 conversion assumed.
     */
    public dert61utf8string(
        string string)
    {
        this(strings.toutf8bytearray(string));
    }

    /**
     * decode the encoded string and return it, utf8 assumed.
     *
     * @return the decoded string
     */
    public string getstring()
    {
        return strings.fromutf8bytearray(string);
    }

    public string tostring()
    {
        return getstring();
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
        out.writeencoded(bertags.t61_string, string);
    }

    /**
     * return the encoded string as a byte array.
     *
     * @return the actual bytes making up the encoded body of the t61 string.
     */
    public byte[] getoctets()
    {
        return arrays.clone(string);
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof dert61utf8string))
        {
            return false;
        }

        return arrays.areequal(string, ((dert61utf8string)o).string);
    }

    public int hashcode()
    {
        return arrays.hashcode(string);
    }
}
