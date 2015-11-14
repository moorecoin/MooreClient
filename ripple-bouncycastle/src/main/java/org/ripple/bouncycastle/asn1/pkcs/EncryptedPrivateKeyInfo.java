package org.ripple.bouncycastle.asn1.pkcs;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class encryptedprivatekeyinfo
    extends asn1object
{
    private algorithmidentifier algid;
    private asn1octetstring     data;

    private encryptedprivatekeyinfo(
        asn1sequence  seq)
    {
        enumeration e = seq.getobjects();

        algid = algorithmidentifier.getinstance(e.nextelement());
        data = asn1octetstring.getinstance(e.nextelement());
    }

    public encryptedprivatekeyinfo(
        algorithmidentifier algid,
        byte[]              encoding)
    {
        this.algid = algid;
        this.data = new deroctetstring(encoding);
    }

    public static encryptedprivatekeyinfo getinstance(
        object  obj)
    {
        if (obj instanceof encryptedprivatekeyinfo)
        {
            return (encryptedprivatekeyinfo)obj;
        }
        else if (obj != null)
        { 
            return new encryptedprivatekeyinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    public algorithmidentifier getencryptionalgorithm()
    {
        return algid;
    }

    public byte[] getencrypteddata()
    {
        return data.getoctets();
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * encryptedprivatekeyinfo ::= sequence {
     *      encryptionalgorithm algorithmidentifier {{keyencryptionalgorithms}},
     *      encrypteddata encrypteddata
     * }
     *
     * encrypteddata ::= octet string
     *
     * keyencryptionalgorithms algorithm-identifier ::= {
     *          ... -- for local profiles
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(algid);
        v.add(data);

        return new dersequence(v);
    }
}
