package org.ripple.bouncycastle.asn1.pkcs;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * @deprecated - use algorithmidentifier and pbes2parameters
 */
public class pbes2algorithms
    extends algorithmidentifier implements pkcsobjectidentifiers
{
    private asn1objectidentifier objectid;
    private keyderivationfunc   func;
    private encryptionscheme scheme;

    public pbes2algorithms(
        asn1sequence  obj)
    {
        super(obj);

        enumeration     e = obj.getobjects();

        objectid = (asn1objectidentifier)e.nextelement();

        asn1sequence seq = (asn1sequence)e.nextelement();

        e = seq.getobjects();

        asn1sequence  funcseq = (asn1sequence)e.nextelement();

        if (funcseq.getobjectat(0).equals(id_pbkdf2))
        {
            func = new keyderivationfunc(id_pbkdf2, pbkdf2params.getinstance(funcseq.getobjectat(1)));
        }
        else
        {
            func = keyderivationfunc.getinstance(funcseq);
        }

        scheme = encryptionscheme.getinstance(e.nextelement());
    }

    public asn1objectidentifier getobjectid()
    {
        return objectid;
    }

    public keyderivationfunc getkeyderivationfunc()
    {
        return func;
    }

    public encryptionscheme getencryptionscheme()
    {
        return scheme;
    }

    public asn1primitive getasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();
        asn1encodablevector  subv = new asn1encodablevector();

        v.add(objectid);

        subv.add(func);
        subv.add(scheme);
        v.add(new dersequence(subv));

        return new dersequence(v);
    }
}
