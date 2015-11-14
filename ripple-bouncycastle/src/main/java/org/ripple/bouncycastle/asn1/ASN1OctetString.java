package org.ripple.bouncycastle.asn1;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.encoders.hex;

public abstract class asn1octetstring
    extends asn1primitive
    implements asn1octetstringparser
{
    byte[]  string;

    /**
     * return an octet string from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *              be converted.
     */
    public static asn1octetstring getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof asn1octetstring)
        {
            return getinstance(o);
        }
        else
        {
            return beroctetstring.fromsequence(asn1sequence.getinstance(o));
        }
    }
    
    /**
     * return an octet string from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static asn1octetstring getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof asn1octetstring)
        {
            return (asn1octetstring)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return asn1octetstring.getinstance(asn1primitive.frombytearray((byte[])obj));
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("failed to construct octet string from byte[]: " + e.getmessage());
            }
        }
        else if (obj instanceof asn1encodable)
        {
            asn1primitive primitive = ((asn1encodable)obj).toasn1primitive();

            if (primitive instanceof asn1octetstring)
            {
                return (asn1octetstring)primitive;
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * @param string the octets making up the octet string.
     */
    public asn1octetstring(
        byte[]  string)
    {
        if (string == null)
        {
            throw new nullpointerexception("string cannot be null");
        }
        this.string = string;
    }

    public inputstream getoctetstream()
    {
        return new bytearrayinputstream(string);
    }

    public asn1octetstringparser parser()
    {
        return this;
    }

    public byte[] getoctets()
    {
        return string;
    }

    public int hashcode()
    {
        return arrays.hashcode(this.getoctets());
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof asn1octetstring))
        {
            return false;
        }

        asn1octetstring  other = (asn1octetstring)o;

        return arrays.areequal(string, other.string);
    }

    public asn1primitive getloadedobject()
    {
        return this.toasn1primitive();
    }

    asn1primitive toderobject()
    {
        return new deroctetstring(string);
    }

    asn1primitive todlobject()
    {
        return new deroctetstring(string);
    }

    abstract void encode(asn1outputstream out)
        throws ioexception;

    public string tostring()
    {
      return "#"+new string(hex.encode(string));
    }
}
