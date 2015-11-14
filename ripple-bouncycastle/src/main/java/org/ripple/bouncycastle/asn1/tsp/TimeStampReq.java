package org.ripple.bouncycastle.asn1.tsp;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.extensions;

public class timestampreq
    extends asn1object
{
    asn1integer version;

    messageimprint messageimprint;

    asn1objectidentifier tsapolicy;

    asn1integer nonce;

    asn1boolean certreq;

    extensions extensions;

    public static timestampreq getinstance(object o)
    {
        if (o instanceof timestampreq)
        {
            return (timestampreq) o;
        }
        else if (o != null)
        {
            return new timestampreq(asn1sequence.getinstance(o));
        }

        return null;
    }

    private timestampreq(asn1sequence seq)
    {
        int nbobjects = seq.size();

        int seqstart = 0;

        // version
        version = asn1integer.getinstance(seq.getobjectat(seqstart));

        seqstart++;

        // messageimprint
        messageimprint = messageimprint.getinstance(seq.getobjectat(seqstart));

        seqstart++;

        for (int opt = seqstart; opt < nbobjects; opt++)
        {
            // tsapolicy
            if (seq.getobjectat(opt) instanceof asn1objectidentifier)
            {
                tsapolicy = asn1objectidentifier.getinstance(seq.getobjectat(opt));
            }
            // nonce
            else if (seq.getobjectat(opt) instanceof asn1integer)
            {
                nonce = asn1integer.getinstance(seq.getobjectat(opt));
            }
            // certreq
            else if (seq.getobjectat(opt) instanceof asn1boolean)
            {
                certreq = asn1boolean.getinstance(seq.getobjectat(opt));
            }
            // extensions
            else if (seq.getobjectat(opt) instanceof asn1taggedobject)
            {
                asn1taggedobject    tagged = (asn1taggedobject)seq.getobjectat(opt);
                if (tagged.gettagno() == 0)
                {
                    extensions = extensions.getinstance(tagged, false);
                }
            }
        }
    }

    public timestampreq(
        messageimprint      messageimprint,
        asn1objectidentifier tsapolicy,
        asn1integer          nonce,
        asn1boolean          certreq,
        extensions      extensions)
    {
        // default
        version = new asn1integer(1);

        this.messageimprint = messageimprint;
        this.tsapolicy = tsapolicy;
        this.nonce = nonce;
        this.certreq = certreq;
        this.extensions = extensions;
    }

    public asn1integer getversion()
    {
        return version;
    }

    public messageimprint getmessageimprint()
    {
        return messageimprint;
    }

    public asn1objectidentifier getreqpolicy()
    {
        return tsapolicy;
    }

    public asn1integer getnonce()
    {
        return nonce;
    }

    public asn1boolean getcertreq()
    {
        return certreq;
    }

    public extensions getextensions()
    {
        return extensions;
    }

    /**
     * <pre>
     * timestampreq ::= sequence  {
     *  version                      integer  { v1(1) },
     *  messageimprint               messageimprint,
     *    --a hash algorithm oid and the hash value of the data to be
     *    --time-stamped
     *  reqpolicy             tsapolicyid              optional,
     *  nonce                 integer                  optional,
     *  certreq               boolean                  default false,
     *  extensions            [0] implicit extensions  optional
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        
        v.add(version);
        v.add(messageimprint);
        
        if (tsapolicy != null)
        {
            v.add(tsapolicy);
        }
        
        if (nonce != null)
        {
            v.add(nonce);
        }
        
        if (certreq != null && certreq.istrue())
        {
            v.add(certreq);
        }
        
        if (extensions != null)
        {
            v.add(new dertaggedobject(false, 0, extensions));
        }

        return new dersequence(v);
    }
}
