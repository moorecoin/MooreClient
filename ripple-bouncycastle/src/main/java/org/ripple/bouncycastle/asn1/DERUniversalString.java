package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;

/**
 * der universalstring object.
 */
public class deruniversalstring
    extends asn1primitive
    implements asn1string
{
    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    private byte[] string;
    
    /**
     * return a universal string from the passed in object.
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static deruniversalstring getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof deruniversalstring)
        {
            return (deruniversalstring)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (deruniversalstring)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return a universal string from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static deruniversalstring getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof deruniversalstring)
        {
            return getinstance(o);
        }
        else
        {
            return new deruniversalstring(((asn1octetstring)o).getoctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     */
    public deruniversalstring(
        byte[]   string)
    {
        this.string = string;
    }

    public string getstring()
    {
        stringbuffer    buf = new stringbuffer("#");
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        asn1outputstream            aout = new asn1outputstream(bout);
        
        try
        {
            aout.writeobject(this);
        }
        catch (ioexception e)
        {
           throw new runtimeexception("internal error encoding bitstring");
        }
        
        byte[]    string = bout.tobytearray();
        
        for (int i = 0; i != string.length; i++)
        {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }
        
        return buf.tostring();
    }

    public string tostring()
    {
        return getstring();
    }

    public byte[] getoctets()
    {
        return string;
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
        out.writeencoded(bertags.universal_string, this.getoctets());
    }
    
    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof deruniversalstring))
        {
            return false;
        }

        return arrays.areequal(string, ((deruniversalstring)o).string);
    }
    
    public int hashcode()
    {
        return arrays.hashcode(string);
    }
}
