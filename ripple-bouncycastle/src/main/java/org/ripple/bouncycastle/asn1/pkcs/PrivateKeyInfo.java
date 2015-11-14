package org.ripple.bouncycastle.asn1.pkcs;

import java.io.ioexception;
import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class privatekeyinfo
    extends asn1object
{
    private asn1octetstring         privkey;
    private algorithmidentifier     algid;
    private asn1set                 attributes;

    public static privatekeyinfo getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static privatekeyinfo getinstance(
        object  obj)
    {
        if (obj instanceof privatekeyinfo)
        {
            return (privatekeyinfo)obj;
        }
        else if (obj != null)
        {
            return new privatekeyinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }
        
    public privatekeyinfo(
        algorithmidentifier algid,
        asn1encodable       privatekey)
        throws ioexception
    {
        this(algid, privatekey, null);
    }

    public privatekeyinfo(
        algorithmidentifier algid,
        asn1encodable       privatekey,
        asn1set             attributes)
        throws ioexception
    {
        this.privkey = new deroctetstring(privatekey.toasn1primitive().getencoded(asn1encoding.der));
        this.algid = algid;
        this.attributes = attributes;
    }

    /**
     * @deprectaed use privatekeyinfo.getinstance()
     * @param seq
     */
    public privatekeyinfo(
        asn1sequence  seq)
    {
        enumeration e = seq.getobjects();

        biginteger  version = ((asn1integer)e.nextelement()).getvalue();
        if (version.intvalue() != 0)
        {
            throw new illegalargumentexception("wrong version for private key info");
        }

        algid = algorithmidentifier.getinstance(e.nextelement());
        privkey = asn1octetstring.getinstance(e.nextelement());
        
        if (e.hasmoreelements())
        {
           attributes = asn1set.getinstance((asn1taggedobject)e.nextelement(), false);
        }
    }

    public algorithmidentifier getprivatekeyalgorithm()
    {
        return algid;
    }
        /**
          * @deprecated use getprivatekeyalgorithm()
     */
    public algorithmidentifier getalgorithmid()
    {
        return algid;
    }

    public asn1encodable parseprivatekey()
        throws ioexception
    {
        return asn1primitive.frombytearray(privkey.getoctets());
    }

    /**
          * @deprecated use parseprivatekey()
     */
    public asn1primitive getprivatekey()
    {
        try
        {
            return parseprivatekey().toasn1primitive();
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("unable to parse private key");
        }
    }
    
    public asn1set getattributes()
    {
        return attributes;
    }

    /**
     * write out an rsa private key with its associated information
     * as described in pkcs8.
     * <pre>
     *      privatekeyinfo ::= sequence {
     *                              version version,
     *                              privatekeyalgorithm algorithmidentifier {{privatekeyalgorithms}},
     *                              privatekey privatekey,
     *                              attributes [0] implicit attributes optional 
     *                          }
     *      version ::= integer {v1(0)} (v1,...)
     *
     *      privatekey ::= octet string
     *
     *      attributes ::= set of attribute
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(new asn1integer(0));
        v.add(algid);
        v.add(privkey);

        if (attributes != null)
        {
            v.add(new dertaggedobject(false, 0, attributes));
        }
        
        return new dersequence(v);
    }
}
