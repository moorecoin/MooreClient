package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.math.biginteger;

import org.ripple.bouncycastle.util.arrays;

public class derinteger
    extends asn1primitive
{
    byte[]      bytes;

    /**
     * return an integer from the passed in object
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static asn1integer getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof asn1integer)
        {
            return (asn1integer)obj;
        }
        if (obj instanceof derinteger)
        {
            return new asn1integer((((derinteger)obj).getvalue()));
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (asn1integer)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an integer from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static asn1integer getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof derinteger)
        {
            return getinstance(o);
        }
        else
        {
            return new asn1integer(asn1octetstring.getinstance(obj.getobject()).getoctets());
        }
    }

    public derinteger(
        long         value)
    {
        bytes = biginteger.valueof(value).tobytearray();
    }

    public derinteger(
        biginteger   value)
    {
        bytes = value.tobytearray();
    }

    public derinteger(
        byte[]   bytes)
    {
        this.bytes = bytes;
    }

    public biginteger getvalue()
    {
        return new biginteger(bytes);
    }

    /**
     * in some cases positive values get crammed into a space,
     * that's not quite big enough...
     */
    public biginteger getpositivevalue()
    {
        return new biginteger(1, bytes);
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
        out.writeencoded(bertags.integer, bytes);
    }
    
    public int hashcode()
    {
         int     value = 0;
 
         for (int i = 0; i != bytes.length; i++)
         {
             value ^= (bytes[i] & 0xff) << (i % 4);
         }
 
         return value;
    }

    boolean asn1equals(
        asn1primitive  o)
    {
        if (!(o instanceof derinteger))
        {
            return false;
        }

        derinteger other = (derinteger)o;

        return arrays.areequal(bytes, other.bytes);
    }

    public string tostring()
    {
      return getvalue().tostring();
    }
}
