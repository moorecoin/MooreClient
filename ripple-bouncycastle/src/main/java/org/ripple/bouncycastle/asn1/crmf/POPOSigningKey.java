package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class poposigningkey
    extends asn1object
{
    private poposigningkeyinput poposkinput;
    private algorithmidentifier algorithmidentifier;
    private derbitstring signature;

    private poposigningkey(asn1sequence seq)
    {
        int index = 0;

        if (seq.getobjectat(index) instanceof asn1taggedobject)
        {
            asn1taggedobject tagobj
                = (asn1taggedobject)seq.getobjectat(index++);
            if (tagobj.gettagno() != 0)
            {
                throw new illegalargumentexception(
                    "unknown poposigningkeyinput tag: " + tagobj.gettagno());
            }
            poposkinput = poposigningkeyinput.getinstance(tagobj.getobject());
        }
        algorithmidentifier = algorithmidentifier.getinstance(seq.getobjectat(index++));
        signature = derbitstring.getinstance(seq.getobjectat(index));
    }

    public static poposigningkey getinstance(object o)
    {
        if (o instanceof poposigningkey)
        {
            return (poposigningkey)o;
        }

        if (o != null)
        {
            return new poposigningkey(asn1sequence.getinstance(o));
        }

        return null;
    }

    public static poposigningkey getinstance(asn1taggedobject obj, boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    /**
     * creates a new proof of possession object for a signing key.
     *
     * @param poposkin  the poposigningkeyinput structure, or null if the
     *                  certtemplate includes both subject and publickey values.
     * @param aid       the algorithmidentifier used to sign the proof of possession.
     * @param signature a signature over the der-encoded value of poposkin,
     *                  or the der-encoded value of certreq if poposkin is null.
     */
    public poposigningkey(
        poposigningkeyinput poposkin,
        algorithmidentifier aid,
        derbitstring signature)
    {
        this.poposkinput = poposkin;
        this.algorithmidentifier = aid;
        this.signature = signature;
    }

    public poposigningkeyinput getpoposkinput()
    {
        return poposkinput;
    }

    public algorithmidentifier getalgorithmidentifier()
    {
        return algorithmidentifier;
    }

    public derbitstring getsignature()
    {
        return signature;
    }

    /**
     * <pre>
     * poposigningkey ::= sequence {
     *                      poposkinput           [0] poposigningkeyinput optional,
     *                      algorithmidentifier   algorithmidentifier,
     *                      signature             bit string }
     *  -- the signature (using "algorithmidentifier") is on the
     *  -- der-encoded value of poposkinput.  note: if the certreqmsg
     *  -- certreq certtemplate contains the subject and publickey values,
     *  -- then poposkinput must be omitted and the signature must be
     *  -- computed on the der-encoded value of certreqmsg certreq.  if
     *  -- the certreqmsg certreq certtemplate does not contain the public
     *  -- key and subject values, then poposkinput must be present and
     *  -- must be signed.  this strategy ensures that the public key is
     *  -- not present in both the poposkinput and certreqmsg certreq
     *  -- certtemplate fields.
     * </pre>
     *
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (poposkinput != null)
        {
            v.add(new dertaggedobject(false, 0, poposkinput));
        }

        v.add(algorithmidentifier);
        v.add(signature);

        return new dersequence(v);
    }
}
