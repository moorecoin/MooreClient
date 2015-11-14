package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class sigpolicyqualifierinfo
    extends asn1object
{
    private asn1objectidentifier  sigpolicyqualifierid;
    private asn1encodable         sigqualifier;

    public sigpolicyqualifierinfo(
        asn1objectidentifier   sigpolicyqualifierid,
        asn1encodable          sigqualifier)
    {
        this.sigpolicyqualifierid = sigpolicyqualifierid;
        this.sigqualifier = sigqualifier;
    }

    private sigpolicyqualifierinfo(
        asn1sequence seq)
    {
        sigpolicyqualifierid = asn1objectidentifier.getinstance(seq.getobjectat(0));
        sigqualifier = seq.getobjectat(1);
    }

    public static sigpolicyqualifierinfo getinstance(
        object obj)
    {
        if (obj instanceof sigpolicyqualifierinfo)
        {
            return (sigpolicyqualifierinfo) obj;
        }
        else if (obj != null)
        {
            return new sigpolicyqualifierinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public asn1objectidentifier getsigpolicyqualifierid()
    {
        return new asn1objectidentifier(sigpolicyqualifierid.getid());
    }

    public asn1encodable getsigqualifier()
    {
        return sigqualifier;
    }

    /**
     * <pre>
     * sigpolicyqualifierinfo ::= sequence {
     *    sigpolicyqualifierid sigpolicyqualifierid,
     *    sigqualifier any defined by sigpolicyqualifierid }
     *
     * sigpolicyqualifierid ::= object identifier
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(sigpolicyqualifierid);
        v.add(sigqualifier);

        return new dersequence(v);
    }
}
