package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.derutctime;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * pkix rfc-2459 - tbscertlist object.
 * <pre>
 * tbscertlist  ::=  sequence  {
 *      version                 version optional,
 *                                   -- if present, shall be v2
 *      signature               algorithmidentifier,
 *      issuer                  name,
 *      thisupdate              time,
 *      nextupdate              time optional,
 *      revokedcertificates     sequence of sequence  {
 *           usercertificate         certificateserialnumber,
 *           revocationdate          time,
 *           crlentryextensions      extensions optional
 *                                         -- if present, shall be v2
 *                                }  optional,
 *      crlextensions           [0]  explicit extensions optional
 *                                         -- if present, shall be v2
 *                                }
 * </pre>
 */
public class tbscertlist
    extends asn1object
{
    public static class crlentry
        extends asn1object
    {
        asn1sequence  seq;

        extensions    crlentryextensions;

        private crlentry(
            asn1sequence  seq)
        {
            if (seq.size() < 2 || seq.size() > 3)
            {
                throw new illegalargumentexception("bad sequence size: " + seq.size());
            }
            
            this.seq = seq;
        }

        public static crlentry getinstance(object o)
        {
            if (o instanceof crlentry)
            {
                return ((crlentry)o);
            }
            else if (o != null)
            {
                return new crlentry(asn1sequence.getinstance(o));
            }

            return null;
        }

        public asn1integer getusercertificate()
        {
            return asn1integer.getinstance(seq.getobjectat(0));
        }

        public time getrevocationdate()
        {
            return time.getinstance(seq.getobjectat(1));
        }

        public extensions getextensions()
        {
            if (crlentryextensions == null && seq.size() == 3)
            {
                crlentryextensions = extensions.getinstance(seq.getobjectat(2));
            }
            
            return crlentryextensions;
        }

        public asn1primitive toasn1primitive()
        {
            return seq;
        }

        public boolean hasextensions()
        {
            return seq.size() == 3;
        }
    }

    private class revokedcertificatesenumeration
        implements enumeration
    {
        private final enumeration en;

        revokedcertificatesenumeration(enumeration en)
        {
            this.en = en;
        }

        public boolean hasmoreelements()
        {
            return en.hasmoreelements();
        }

        public object nextelement()
        {
            return crlentry.getinstance(en.nextelement());
        }
    }

    private class emptyenumeration
        implements enumeration
    {
        public boolean hasmoreelements()
        {
            return false;
        }

        public object nextelement()
        {
            return null;   // todo: check exception handling
        }
    }

    asn1integer             version;
    algorithmidentifier     signature;
    x500name                issuer;
    time                    thisupdate;
    time                    nextupdate;
    asn1sequence            revokedcertificates;
    extensions              crlextensions;

    public static tbscertlist getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static tbscertlist getinstance(
        object  obj)
    {
        if (obj instanceof tbscertlist)
        {
            return (tbscertlist)obj;
        }
        else if (obj != null)
        {
            return new tbscertlist(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public tbscertlist(
        asn1sequence  seq)
    {
        if (seq.size() < 3 || seq.size() > 7)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        int seqpos = 0;

        if (seq.getobjectat(seqpos) instanceof asn1integer)
        {
            version = asn1integer.getinstance(seq.getobjectat(seqpos++));
        }
        else
        {
            version = null;  // version is optional
        }

        signature = algorithmidentifier.getinstance(seq.getobjectat(seqpos++));
        issuer = x500name.getinstance(seq.getobjectat(seqpos++));
        thisupdate = time.getinstance(seq.getobjectat(seqpos++));

        if (seqpos < seq.size()
            && (seq.getobjectat(seqpos) instanceof derutctime
               || seq.getobjectat(seqpos) instanceof dergeneralizedtime
               || seq.getobjectat(seqpos) instanceof time))
        {
            nextupdate = time.getinstance(seq.getobjectat(seqpos++));
        }

        if (seqpos < seq.size()
            && !(seq.getobjectat(seqpos) instanceof dertaggedobject))
        {
            revokedcertificates = asn1sequence.getinstance(seq.getobjectat(seqpos++));
        }

        if (seqpos < seq.size()
            && seq.getobjectat(seqpos) instanceof dertaggedobject)
        {
            crlextensions = extensions.getinstance(asn1sequence.getinstance((asn1taggedobject)seq.getobjectat(seqpos), true));
        }
    }

    public int getversionnumber()
    {
        if (version == null)
        {
            return 1;
        }
        return version.getvalue().intvalue() + 1;
    }

    public asn1integer getversion()
    {
        return version;
    }

    public algorithmidentifier getsignature()
    {
        return signature;
    }

    public x500name getissuer()
    {
        return issuer;
    }

    public time getthisupdate()
    {
        return thisupdate;
    }

    public time getnextupdate()
    {
        return nextupdate;
    }

    public crlentry[] getrevokedcertificates()
    {
        if (revokedcertificates == null)
        {
            return new crlentry[0];
        }

        crlentry[] entries = new crlentry[revokedcertificates.size()];

        for (int i = 0; i < entries.length; i++)
        {
            entries[i] = crlentry.getinstance(revokedcertificates.getobjectat(i));
        }
        
        return entries;
    }

    public enumeration getrevokedcertificateenumeration()
    {
        if (revokedcertificates == null)
        {
            return new emptyenumeration();
        }

        return new revokedcertificatesenumeration(revokedcertificates.getobjects());
    }

    public extensions getextensions()
    {
        return crlextensions;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (version != null)
        {
            v.add(version);
        }
        v.add(signature);
        v.add(issuer);

        v.add(thisupdate);
        if (nextupdate != null)
        {
            v.add(nextupdate);
        }

        // add crlentries if they exist
        if (revokedcertificates != null)
        {
            v.add(revokedcertificates);
        }

        if (crlextensions != null)
        {
            v.add(new dertaggedobject(0, crlextensions));
        }

        return new dersequence(v);
    }
}
