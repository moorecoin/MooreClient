package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * @deprecated use org.bouncycastle.asn1.pkcs.rsapublickey
 */
public class rsapublickeystructure
    extends asn1object
{
    private biginteger  modulus;
    private biginteger  publicexponent;

    public static rsapublickeystructure getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static rsapublickeystructure getinstance(
        object obj)
    {
        if(obj == null || obj instanceof rsapublickeystructure) 
        {
            return (rsapublickeystructure)obj;
        }
        
        if(obj instanceof asn1sequence) 
        {
            return new rsapublickeystructure((asn1sequence)obj);
        }
        
        throw new illegalargumentexception("invalid rsapublickeystructure: " + obj.getclass().getname());
    }
    
    public rsapublickeystructure(
        biginteger  modulus,
        biginteger  publicexponent)
    {
        this.modulus = modulus;
        this.publicexponent = publicexponent;
    }

    public rsapublickeystructure(
        asn1sequence  seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }

        enumeration e = seq.getobjects();

        modulus = asn1integer.getinstance(e.nextelement()).getpositivevalue();
        publicexponent = asn1integer.getinstance(e.nextelement()).getpositivevalue();
    }

    public biginteger getmodulus()
    {
        return modulus;
    }

    public biginteger getpublicexponent()
    {
        return publicexponent;
    }

    /**
     * this outputs the key in pkcs1v2 format.
     * <pre>
     *      rsapublickey ::= sequence {
     *                          modulus integer, -- n
     *                          publicexponent integer, -- e
     *                      }
     * </pre>
     * <p>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(new asn1integer(getmodulus()));
        v.add(new asn1integer(getpublicexponent()));

        return new dersequence(v);
    }
}
