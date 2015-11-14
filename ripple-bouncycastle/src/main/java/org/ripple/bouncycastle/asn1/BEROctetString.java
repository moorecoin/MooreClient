package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.util.enumeration;
import java.util.vector;

public class beroctetstring
    extends asn1octetstring
{
    private static final int max_length = 1000;

    private asn1octetstring[] octs;

    /**
     * convert a vector of octet strings into a single byte string
     */
    static private byte[] tobytes(
        asn1octetstring[]  octs)
    {
        bytearrayoutputstream bout = new bytearrayoutputstream();

        for (int i = 0; i != octs.length; i++)
        {
            try
            {
                deroctetstring o = (deroctetstring)octs[i];

                bout.write(o.getoctets());
            }
            catch (classcastexception e)
            {
                throw new illegalargumentexception(octs[i].getclass().getname() + " found in input should only contain deroctetstring");
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("exception converting octets " + e.tostring());
            }
        }

        return bout.tobytearray();
    }

    /**
     * @param string the octets making up the octet string.
     */
    public beroctetstring(
        byte[] string)
    {
        super(string);
    }

    public beroctetstring(
        asn1octetstring[] octs)
    {
        super(tobytes(octs));

        this.octs = octs;
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

        return new enumeration()
        {
            int counter = 0;

            public boolean hasmoreelements()
            {
                return counter < octs.length;
            }

            public object nextelement()
            {
                return octs[counter++];
            }
        };
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

    boolean isconstructed()
    {
        return true;
    }

    int encodedlength()
        throws ioexception
    {
        int length = 0;
        for (enumeration e = getobjects(); e.hasmoreelements();)
        {
            length += ((asn1encodable)e.nextelement()).toasn1primitive().encodedlength();
        }

        return 2 + length + 2;
    }

    public void encode(
        asn1outputstream out)
        throws ioexception
    {
        out.write(bertags.constructed | bertags.octet_string);

        out.write(0x80);

        //
        // write out the octet array
        //
        for (enumeration e = getobjects(); e.hasmoreelements();)
        {
            out.writeobject((asn1encodable)e.nextelement());
        }

        out.write(0x00);
        out.write(0x00);
    }

    static beroctetstring fromsequence(asn1sequence seq)
    {
        asn1octetstring[]     v = new asn1octetstring[seq.size()];
        enumeration e = seq.getobjects();
        int                   index = 0;

        while (e.hasmoreelements())
        {
            v[index++] = (asn1octetstring)e.nextelement();
        }

        return new beroctetstring(v);
    }
}
