package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * der t61string (also the teletex string), try not to use this if you don't need to. the standard support the encoding for
 * this has been withdrawn.
 */
public class dert61string
    extends asn1primitive
    implements asn1string
{
    private byte[] string;

    /**
     * return a t61 string from the passed in object.
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static dert61string getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof dert61string)
        {
            return (dert61string)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (dert61string)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an t61 string from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static dert61string getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof dert61string)
        {
            return getinstance(o);
        }
        else
        {
            return new dert61string(asn1octetstring.getinstance(o).getoctets());
        }
    }

    /**
     * basic constructor - string encoded as a sequence of bytes.
     */
    public dert61string(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * basic constructor - with string 8 bit assumed.
     */
    public dert61string(
        string   string)
    {
        this(strings.tobytearray(string));
    }

    /**
     * decode the encoded string and return it, 8 bit encoding assumed.
     * @return the decoded string
     */
    public string getstring()
    {
        return strings.frombytearray(string);
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
     * @return the actual bytes making up the encoded body of the t61 string.
     */
    public byte[] getoctets()
    {
        return arrays.clone(string);
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof dert61string))
        {
            return false;
        }

        return arrays.areequal(string, ((dert61string)o).string);
    }
    
    public int hashcode()
    {
        return arrays.hashcode(string);
    }
}
