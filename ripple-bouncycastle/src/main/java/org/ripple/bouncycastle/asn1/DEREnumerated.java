package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.math.biginteger;

import org.ripple.bouncycastle.util.arrays;

public class derenumerated
    extends asn1primitive
{
    byte[]      bytes;

    /**
     * return an integer from the passed in object
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static asn1enumerated getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof asn1enumerated)
        {
            return (asn1enumerated)obj;
        }

        if (obj instanceof derenumerated)
        {
            return new asn1enumerated(((derenumerated)obj).getvalue());
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (asn1enumerated)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an enumerated from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static derenumerated getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof derenumerated)
        {
            return getinstance(o);
        }
        else
        {
            return fromoctetstring(((asn1octetstring)o).getoctets());
        }
    }

    public derenumerated(
        int         value)
    {
        bytes = biginteger.valueof(value).tobytearray();
    }

    public derenumerated(
        biginteger   value)
    {
        bytes = value.tobytearray();
    }

    public derenumerated(
        byte[]   bytes)
    {
        this.bytes = bytes;
    }

    public biginteger getvalue()
    {
        return new biginteger(bytes);
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
    {
        return 1 + streamutil.calculatebodylength(bytes.length) + bytes.length;
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        out.writeencoded(bertags.enumerated, bytes);
    }
    
    boolean asn1equals(
        asn1primitive  o)
    {
        if (!(o instanceof derenumerated))
        {
            return false;
        }

        derenumerated other = (derenumerated)o;

        return arrays.areequal(this.bytes, other.bytes);
    }

    public int hashcode()
    {
        return arrays.hashcode(bytes);
    }

    private static asn1enumerated[] cache = new asn1enumerated[12];

    static asn1enumerated fromoctetstring(byte[] enc)
    {
        if (enc.length > 1)
        {
            return new asn1enumerated(arrays.clone(enc));
        }

        if (enc.length == 0)
        {
            throw new illegalargumentexception("enumerated has zero length");
        }
        int value = enc[0] & 0xff;

        if (value >= cache.length)
        {
            return new asn1enumerated(arrays.clone(enc));
        }

        asn1enumerated possiblematch = cache[value];

        if (possiblematch == null)
        {
            possiblematch = cache[value] = new asn1enumerated(arrays.clone(enc));
        }

        return possiblematch;
    }
}
