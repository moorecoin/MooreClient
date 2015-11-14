package org.ripple.bouncycastle.asn1.tsp;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.generalname;

public class tstinfo
    extends asn1object
{
    private asn1integer version;
    private asn1objectidentifier tsapolicyid;
    private messageimprint messageimprint;
    private asn1integer serialnumber;
    private asn1generalizedtime gentime;
    private accuracy accuracy;
    private asn1boolean ordering;
    private asn1integer nonce;
    private generalname tsa;
    private extensions extensions;

    public static tstinfo getinstance(object o)
    {
        if (o instanceof tstinfo)
        {
            return (tstinfo)o;
        }
        else if (o != null)
        {
            return new tstinfo(asn1sequence.getinstance(o));
        }

        return null;
    }

    private tstinfo(asn1sequence seq)
    {
        enumeration e = seq.getobjects();

        // version
        version = asn1integer.getinstance(e.nextelement());

        // tsapolicy
        tsapolicyid = asn1objectidentifier.getinstance(e.nextelement());

        // messageimprint
        messageimprint = messageimprint.getinstance(e.nextelement());

        // serialnumber
        serialnumber = asn1integer.getinstance(e.nextelement());

        // gentime
        gentime = asn1generalizedtime.getinstance(e.nextelement());

        // default for ordering
        ordering = asn1boolean.getinstance(false);
        
        while (e.hasmoreelements())
        {
            asn1object o = (asn1object) e.nextelement();

            if (o instanceof asn1taggedobject)
            {
                dertaggedobject tagged = (dertaggedobject) o;

                switch (tagged.gettagno())
                {
                case 0:
                    tsa = generalname.getinstance(tagged, true);
                    break;
                case 1:
                    extensions = extensions.getinstance(tagged, false);
                    break;
                default:
                    throw new illegalargumentexception("unknown tag value " + tagged.gettagno());
                }
            }
            else if (o instanceof asn1sequence || o instanceof accuracy)
            {
                accuracy = accuracy.getinstance(o);
            }
            else if (o instanceof asn1boolean)
            {
                ordering = asn1boolean.getinstance(o);
            }
            else if (o instanceof asn1integer)
            {
                nonce = asn1integer.getinstance(o);
            }

        }
    }

    public tstinfo(asn1objectidentifier tsapolicyid, messageimprint messageimprint,
            asn1integer serialnumber, asn1generalizedtime gentime,
            accuracy accuracy, asn1boolean ordering, asn1integer nonce,
            generalname tsa, extensions extensions)
    {
        version = new asn1integer(1);
        this.tsapolicyid = tsapolicyid;
        this.messageimprint = messageimprint;
        this.serialnumber = serialnumber;
        this.gentime = gentime;

        this.accuracy = accuracy;
        this.ordering = ordering;
        this.nonce = nonce;
        this.tsa = tsa;
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

    public asn1objectidentifier getpolicy()
    {
        return tsapolicyid;
    }

    public asn1integer getserialnumber()
    {
        return serialnumber;
    }

    public accuracy getaccuracy()
    {
        return accuracy;
    }

    public asn1generalizedtime getgentime()
    {
        return gentime;
    }

    public asn1boolean getordering()
    {
        return ordering;
    }

    public asn1integer getnonce()
    {
        return nonce;
    }

    public generalname gettsa()
    {
        return tsa;
    }

    public extensions getextensions()
    {
        return extensions;
    }

    /**
     * <pre>
     * 
     *     tstinfo ::= sequence  {
     *        version                      integer  { v1(1) },
     *        policy                       tsapolicyid,
     *        messageimprint               messageimprint,
     *          -- must have the same value as the similar field in
     *          -- timestampreq
     *        serialnumber                 integer,
     *         -- time-stamping users must be ready to accommodate integers
     *         -- up to 160 bits.
     *        gentime                      generalizedtime,
     *        accuracy                     accuracy                 optional,
     *        ordering                     boolean             default false,
     *        nonce                        integer                  optional,
     *          -- must be present if the similar field was present
     *          -- in timestampreq.  in that case it must have the same value.
     *        tsa                          [0] generalname          optional,
     *        extensions                   [1] implicit extensions   optional  }
     * 
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();
        seq.add(version);

        seq.add(tsapolicyid);
        seq.add(messageimprint);
        seq.add(serialnumber);
        seq.add(gentime);

        if (accuracy != null)
        {
            seq.add(accuracy);
        }
        
        if (ordering != null && ordering.istrue())
        {
            seq.add(ordering);
        }
        
        if (nonce != null)
        {
            seq.add(nonce);
        }
        
        if (tsa != null)
        {
            seq.add(new dertaggedobject(true, 0, tsa));
        }
        
        if (extensions != null)
        {
            seq.add(new dertaggedobject(false, 1, extensions));
        }

        return new dersequence(seq);
    }
}
