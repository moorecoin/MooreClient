package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.util.enumeration;
import java.util.vector;

/**
 * @deprecated use beroctetstring
 */
public class berconstructedoctetstring
    extends beroctetstring
{
    private static final int max_length = 1000;

    /**
     * convert a vector of octet strings into a single byte string
     */
    static private byte[] tobytes(
        vector  octs)
    {
        bytearrayoutputstream   bout = new bytearrayoutputstream();

        for (int i = 0; i != octs.size(); i++)
        {
            try
            {
                deroctetstring  o = (deroctetstring)octs.elementat(i);

                bout.write(o.getoctets());
            }
            catch (classcastexception e)
            {
                throw new illegalargumentexception(octs.elementat(i).getclass().getname() + " found in input should only contain deroctetstring");
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("exception converting octets " + e.tostring());
            }
        }

        return bout.tobytearray();
    }

    private vector  octs;

    /**
     * @param string the octets making up the octet string.
     */
    public berconstructedoctetstring(
        byte[]  string)
    {
        super(string);
    }

    public berconstructedoctetstring(
        vector  octs)
    {
        super(tobytes(octs));

        this.octs = octs;
    }

    public berconstructedoctetstring(
        asn1primitive  obj)
    {
        super(tobytearray(obj));
    }

    private static byte[] tobytearray(asn1primitive obj)
    {
        try
        {
            return obj.getencoded();
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("unable to encode object");
        }
    }

    public berconstructedoctetstring(
        asn1encodable  obj)
    {
        this(obj.toasn1primitive());
    }

    public byte[] getoctets()
    {
        return string;
    }

    /**
     * return the der octets that make up this string.
     */
    public enumeration getobjects()
    {
        if (octs == null)
        {
            return generateocts().elements();
        }

        return octs.elements();
    }

    private vector generateocts() 
    { 
        vector vec = new vector(); 
        for (int i = 0; i < string.length; i += max_length) 
        { 
            int end; 

            if (i + max_length > string.length) 
            { 
                end = string.length; 
            } 
            else 
            { 
                end = i + max_length; 
            } 

            byte[] nstr = new byte[end - i]; 

            system.arraycopy(string, i, nstr, 0, nstr.length); 

            vec.addelement(new deroctetstring(nstr)); 
         } 
        
         return vec; 
    }

    public static beroctetstring fromsequence(asn1sequence seq)
    {
        vector      v = new vector();
        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            v.addelement(e.nextelement());
        }

        return new berconstructedoctetstring(v);
    }
}
