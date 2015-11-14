package org.ripple.bouncycastle.asn1.pkcs;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class pbes2parameters
    extends asn1object
    implements pkcsobjectidentifiers
{
    private keyderivationfunc func;
    private encryptionscheme scheme;

    public static pbes2parameters getinstance(
        object  obj)
    {
        if (obj instanceof pbes2parameters)
        {
            return (pbes2parameters)obj;
        }
        if (obj != null)
        {
            return new pbes2parameters(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public pbes2parameters(keyderivationfunc keydevfunc, encryptionscheme encscheme)
    {
        this.func = keydevfunc;
        this.scheme = encscheme;
    }

    private pbes2parameters(
        asn1sequence  obj)
    {
        enumeration e = obj.getobjects();
        asn1sequence  funcseq = asn1sequence.getinstance(((asn1encodable)e.nextelement()).toasn1primitive());

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

    public keyderivationfunc getkeyderivationfunc()
    {
        return func;
    }

    public encryptionscheme getencryptionscheme()
    {
        return scheme;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(func);
        v.add(scheme);

        return new dersequence(v);
    }
}
