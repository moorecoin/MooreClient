package org.ripple.bouncycastle.asn1.pkcs;

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
 * @deprecated use rsaprivatekey
 */
public class rsaprivatekeystructure
    extends asn1object
{
    private int         version;
    private biginteger  modulus;
    private biginteger  publicexponent;
    private biginteger  privateexponent;
    private biginteger  prime1;
    private biginteger  prime2;
    private biginteger  exponent1;
    private biginteger  exponent2;
    private biginteger  coefficient;
    private asn1sequence otherprimeinfos = null;

    public static rsaprivatekeystructure getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static rsaprivatekeystructure getinstance(
        object  obj)
    {
        if (obj instanceof rsaprivatekeystructure)
        {
            return (rsaprivatekeystructure)obj;
        }
        else if (obj instanceof asn1sequence)
        {
            return new rsaprivatekeystructure((asn1sequence)obj);
        }

        throw new illegalargumentexception("unknown object in factory: " + obj.getclass().getname());
    }
    
    public rsaprivatekeystructure(
        biginteger  modulus,
        biginteger  publicexponent,
        biginteger  privateexponent,
        biginteger  prime1,
        biginteger  prime2,
        biginteger  exponent1,
        biginteger  exponent2,
        biginteger  coefficient)
    {
        this.version = 0;
        this.modulus = modulus;
        this.publicexponent = publicexponent;
        this.privateexponent = privateexponent;
        this.prime1 = prime1;
        this.prime2 = prime2;
        this.exponent1 = exponent1;
        this.exponent2 = exponent2;
        this.coefficient = coefficient;
    }

    public rsaprivatekeystructure(
        asn1sequence  seq)
    {
        enumeration e = seq.getobjects();

        biginteger  v = ((asn1integer)e.nextelement()).getvalue();
        if (v.intvalue() != 0 && v.intvalue() != 1)
        {
            throw new illegalargumentexception("wrong version for rsa private key");
        }

        version = v.intvalue();
        modulus = ((asn1integer)e.nextelement()).getvalue();
        publicexponent = ((asn1integer)e.nextelement()).getvalue();
        privateexponent = ((asn1integer)e.nextelement()).getvalue();
        prime1 = ((asn1integer)e.nextelement()).getvalue();
        prime2 = ((asn1integer)e.nextelement()).getvalue();
        exponent1 = ((asn1integer)e.nextelement()).getvalue();
        exponent2 = ((asn1integer)e.nextelement()).getvalue();
        coefficient = ((asn1integer)e.nextelement()).getvalue();
        
        if (e.hasmoreelements())
        {
            otherprimeinfos = (asn1sequence)e.nextelement();
        }
    }

    public int getversion()
    {
        return version;
    }
    
    public biginteger getmodulus()
    {
        return modulus;
    }

    public biginteger getpublicexponent()
    {
        return publicexponent;
    }

    public biginteger getprivateexponent()
    {
        return privateexponent;
    }

    public biginteger getprime1()
    {
        return prime1;
    }

    public biginteger getprime2()
    {
        return prime2;
    }

    public biginteger getexponent1()
    {
        return exponent1;
    }

    public biginteger getexponent2()
    {
        return exponent2;
    }

    public biginteger getcoefficient()
    {
        return coefficient;
    }

    /**
     * this outputs the key in pkcs1v2 format.
     * <pre>
     *      rsaprivatekey ::= sequence {
     *                          version version,
     *                          modulus integer, -- n
     *                          publicexponent integer, -- e
     *                          privateexponent integer, -- d
     *                          prime1 integer, -- p
     *                          prime2 integer, -- q
     *                          exponent1 integer, -- d mod (p-1)
     *                          exponent2 integer, -- d mod (q-1)
     *                          coefficient integer, -- (inverse of q) mod p
     *                          otherprimeinfos otherprimeinfos optional
     *                      }
     *
     *      version ::= integer { two-prime(0), multi(1) }
     *        (constrained by {-- version must be multi if otherprimeinfos present --})
     * </pre>
     * <p>
     * this routine is written to output pkcs1 version 2.1, private keys.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(new asn1integer(version));                       // version
        v.add(new asn1integer(getmodulus()));
        v.add(new asn1integer(getpublicexponent()));
        v.add(new asn1integer(getprivateexponent()));
        v.add(new asn1integer(getprime1()));
        v.add(new asn1integer(getprime2()));
        v.add(new asn1integer(getexponent1()));
        v.add(new asn1integer(getexponent2()));
        v.add(new asn1integer(getcoefficient()));

        if (otherprimeinfos != null)
        {
            v.add(otherprimeinfos);
        }
        
        return new dersequence(v);
    }
}
