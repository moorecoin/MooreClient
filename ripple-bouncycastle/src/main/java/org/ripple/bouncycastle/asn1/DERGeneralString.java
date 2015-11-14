package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

public class dergeneralstring 
    extends asn1primitive
    implements asn1string
{
    private byte[] string;

    public static dergeneralstring getinstance(
        object obj) 
    {
        if (obj == null || obj instanceof dergeneralstring) 
        {
            return (dergeneralstring) obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (dergeneralstring)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: "
                + obj.getclass().getname());
    }

    public static dergeneralstring getinstance(
        asn1taggedobject obj, 
        boolean explicit) 
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof dergeneralstring)
        {
            return getinstance(o);
        }
        else
        {
            return new dergeneralstring(((asn1octetstring)o).getoctets());
        }
    }

    dergeneralstring(byte[] string)
    {
        this.string = string;
    }

    public dergeneralstring(string string) 
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

    void encode(asn1outputstream out)
        throws ioexception 
    {
        out.writeencoded(bertags.general_string, string);
    }
    
    public int hashcode() 
    {
        return arrays.hashcode(string);
    }
    
    boolean asn1equals(asn1primitive o)
    {
        if (!(o instanceof dergeneralstring)) 
        {
            return false;
        }
        dergeneralstring s = (dergeneralstring)o;

        return arrays.areequal(string, s.string);
    }
}
