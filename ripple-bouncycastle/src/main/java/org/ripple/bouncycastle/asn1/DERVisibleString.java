package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * der visiblestring object.
 */
public class dervisiblestring
    extends asn1primitive
    implements asn1string
{
    private byte[]  string;

    /**
     * return a visible string from the passed in object.
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static dervisiblestring getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof dervisiblestring)
        {
            return (dervisiblestring)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (dervisiblestring)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return a visible string from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static dervisiblestring getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof dervisiblestring)
        {
            return getinstance(o);
        }
        else
        {
            return new dervisiblestring(asn1octetstring.getinstance(o).getoctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     */
    dervisiblestring(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * basic constructor
     */
    public dervisiblestring(
        string   string)
    {
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
        out.writeencoded(bertags.visible_string, this.string);
    }
    
    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof dervisiblestring))
        {
            return false;
        }

        return arrays.areequal(string, ((dervisiblestring)o).string);
    }
    
    public int hashcode()
    {
        return arrays.hashcode(string);
    }
}
