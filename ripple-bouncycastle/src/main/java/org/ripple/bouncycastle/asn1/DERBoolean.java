package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;

public class derboolean
    extends asn1primitive
{
    private static final byte[] true_value = new byte[] { (byte)0xff };
    private static final byte[] false_value = new byte[] { 0 };

    private byte[]         value;

    public static final asn1boolean false = new asn1boolean(false);
    public static final asn1boolean true  = new asn1boolean(true);


    /**
     * return a boolean from the passed in object.
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static asn1boolean getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof asn1boolean)
        {
            return (asn1boolean)obj;
        }

        if (obj instanceof derboolean)
        {
            return ((derboolean)obj).istrue() ? derboolean.true : derboolean.false;
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return a asn1boolean from the passed in boolean.
     */
    public static asn1boolean getinstance(
        boolean  value)
    {
        return (value ? true : false);
    }

    /**
     * return a asn1boolean from the passed in boolean.
     */
    public static asn1boolean getinstance(
        int value)
    {
        return (value != 0 ? true : false);
    }

    /**
     * return a boolean from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static asn1boolean getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof derboolean)
        {
            return getinstance(o);
        }
        else
        {
            return asn1boolean.fromoctetstring(((asn1octetstring)o).getoctets());
        }
    }
    
    derboolean(
        byte[]       value)
    {
        if (value.length != 1)
        {
            throw new illegalargumentexception("byte value should have 1 byte in it");
        }

        if (value[0] == 0)
        {
            this.value = false_value;
        }
        else if (value[0] == 0xff)
        {
            this.value = true_value;
        }
        else
        {
            this.value = arrays.clone(value);
        }
    }

    /**
     * @deprecated use getinstance(boolean) method.
     * @param value
     */
    public derboolean(
        boolean     value)
    {
        this.value = (value) ? true_value : false_value;
    }

    public boolean istrue()
    {
        return (value[0] != 0);
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
    {
        return 3;
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        out.writeencoded(bertags.boolean, value);
    }
    
    protected boolean asn1equals(
        asn1primitive  o)
    {
        if ((o == null) || !(o instanceof derboolean))
        {
            return false;
        }

        return (value[0] == ((derboolean)o).value[0]);
    }
    
    public int hashcode()
    {
        return value[0];
    }


    public string tostring()
    {
      return (value[0] != 0) ? "true" : "false";
    }

    static asn1boolean fromoctetstring(byte[] value)
    {
        if (value.length != 1)
        {
            throw new illegalargumentexception("byte value should have 1 byte in it");
        }

        if (value[0] == 0)
        {
            return false;
        }
        else if (value[0] == 0xff)
        {
            return true;
        }
        else
        {
            return new asn1boolean(value);
        }
    }
}
