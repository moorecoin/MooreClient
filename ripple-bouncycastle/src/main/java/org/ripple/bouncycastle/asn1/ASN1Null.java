package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

/**
 * a null object.
 */
public abstract class asn1null
    extends asn1primitive
{
    /**
     * @deprecated use dernull.instance
     */
    public asn1null()
    {
    }

    public static asn1null getinstance(object o)
    {
        if (o instanceof asn1null)
        {
            return (asn1null)o;
        }

        if (o != null)
        {
            try
            {
                return asn1null.getinstance(asn1primitive.frombytearray((byte[])o));
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("failed to construct null from byte[]: " + e.getmessage());
            }
            catch (classcastexception e)
            {
                throw new illegalargumentexception("unknown object in getinstance(): " + o.getclass().getname());
            }
        }

        return null;
    }

    public int hashcode()
    {
        return -1;
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof asn1null))
        {
            return false;
        }
        
        return true;
    }

    abstract void encode(asn1outputstream out)
        throws ioexception;

    public string tostring()
    {
         return "null";
    }
}
