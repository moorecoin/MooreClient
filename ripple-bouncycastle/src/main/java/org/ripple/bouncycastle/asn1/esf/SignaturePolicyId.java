package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class signaturepolicyid
    extends asn1object
{
    private asn1objectidentifier  sigpolicyid;
    private otherhashalgandvalue sigpolicyhash;
    private sigpolicyqualifiers  sigpolicyqualifiers;


    public static signaturepolicyid getinstance(
        object obj)
    {
        if (obj instanceof signaturepolicyid)
        {
            return (signaturepolicyid)obj;
        }
        else if (obj != null)
        {
            return new signaturepolicyid(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private signaturepolicyid(
        asn1sequence seq)
    {
        if (seq.size() != 2 && seq.size() != 3)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        sigpolicyid = asn1objectidentifier.getinstance(seq.getobjectat(0));
        sigpolicyhash = otherhashalgandvalue.getinstance(seq.getobjectat(1));

        if (seq.size() == 3)
        {
            sigpolicyqualifiers = sigpolicyqualifiers.getinstance(seq.getobjectat(2));
        }
    }

    public signaturepolicyid(
        asn1objectidentifier   sigpolicyidentifier,
        otherhashalgandvalue  sigpolicyhash)
    {
        this(sigpolicyidentifier, sigpolicyhash, null);
    }

    public signaturepolicyid(
        asn1objectidentifier   sigpolicyid,
        otherhashalgandvalue  sigpolicyhash,
        sigpolicyqualifiers   sigpolicyqualifiers)
    {
        this.sigpolicyid = sigpolicyid;
        this.sigpolicyhash = sigpolicyhash;
        this.sigpolicyqualifiers = sigpolicyqualifiers;
    }

    public asn1objectidentifier getsigpolicyid()
    {
        return new asn1objectidentifier(sigpolicyid.getid());
    }

    public otherhashalgandvalue getsigpolicyhash()
    {
        return sigpolicyhash;
    }

    public sigpolicyqualifiers getsigpolicyqualifiers()
    {
        return sigpolicyqualifiers;
    }

    /**
     * <pre>
     * signaturepolicyid ::= sequence {
     *     sigpolicyid sigpolicyid,
     *     sigpolicyhash sigpolicyhash,
     *     sigpolicyqualifiers sequence size (1..max) of sigpolicyqualifierinfo optional}
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(sigpolicyid);
        v.add(sigpolicyhash);
        if (sigpolicyqualifiers != null)
        {
            v.add(sigpolicyqualifiers);
        }

        return new dersequence(v);
    }
}
