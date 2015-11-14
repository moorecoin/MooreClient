package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

public class singleresponse
    extends asn1object
{
    private certid              certid;
    private certstatus          certstatus;
    private asn1generalizedtime  thisupdate;
    private asn1generalizedtime  nextupdate;
    private extensions      singleextensions;

    /**
     * @deprecated use method taking asn1generalizedtime and extensions
     * @param certid
     * @param certstatus
     * @param thisupdate
     * @param nextupdate
     * @param singleextensions
     */
    public singleresponse(
        certid              certid,
        certstatus          certstatus,
        dergeneralizedtime  thisupdate,
        dergeneralizedtime  nextupdate,
        x509extensions singleextensions)
    {
        this(certid, certstatus, thisupdate, nextupdate, extensions.getinstance(singleextensions));
    }

    /**
     * @deprecated use method taking asn1generalizedtime and extensions
     * @param certid
     * @param certstatus
     * @param thisupdate
     * @param nextupdate
     * @param singleextensions
     */
    public singleresponse(
        certid              certid,
        certstatus          certstatus,
        dergeneralizedtime thisupdate,
        dergeneralizedtime nextupdate,
        extensions          singleextensions)
    {
        this(certid, certstatus, asn1generalizedtime.getinstance(thisupdate), asn1generalizedtime.getinstance(nextupdate), extensions.getinstance(singleextensions));
    }

    public singleresponse(
        certid              certid,
        certstatus          certstatus,
        asn1generalizedtime thisupdate,
        asn1generalizedtime nextupdate,
        extensions          singleextensions)
    {
        this.certid = certid;
        this.certstatus = certstatus;
        this.thisupdate = thisupdate;
        this.nextupdate = nextupdate;
        this.singleextensions = singleextensions;
    }

    private singleresponse(
        asn1sequence    seq)
    {
        this.certid = certid.getinstance(seq.getobjectat(0));
        this.certstatus = certstatus.getinstance(seq.getobjectat(1));
        this.thisupdate = asn1generalizedtime.getinstance(seq.getobjectat(2));

        if (seq.size() > 4)
        {
            this.nextupdate = asn1generalizedtime.getinstance(
                                (asn1taggedobject)seq.getobjectat(3), true);
            this.singleextensions = extensions.getinstance(
                                (asn1taggedobject)seq.getobjectat(4), true);
        }
        else if (seq.size() > 3)
        {
            asn1taggedobject    o = (asn1taggedobject)seq.getobjectat(3);

            if (o.gettagno() == 0)
            {
                this.nextupdate = asn1generalizedtime.getinstance(o, true);
            }
            else
            {
                this.singleextensions = extensions.getinstance(o, true);
            }
        }
    }

    public static singleresponse getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static singleresponse getinstance(
        object  obj)
    {
        if (obj instanceof singleresponse)
        {
            return (singleresponse)obj;
        }
        else if (obj != null)
        {
            return new singleresponse(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public certid getcertid()
    {
        return certid;
    }

    public certstatus getcertstatus()
    {
        return certstatus;
    }

    public asn1generalizedtime getthisupdate()
    {
        return thisupdate;
    }

    public asn1generalizedtime getnextupdate()
    {
        return nextupdate;
    }

    public extensions getsingleextensions()
    {
        return singleextensions;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  singleresponse ::= sequence {
     *          certid                       certid,
     *          certstatus                   certstatus,
     *          thisupdate                   generalizedtime,
     *          nextupdate         [0]       explicit generalizedtime optional,
     *          singleextensions   [1]       explicit extensions optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certid);
        v.add(certstatus);
        v.add(thisupdate);

        if (nextupdate != null)
        {
            v.add(new dertaggedobject(true, 0, nextupdate));
        }

        if (singleextensions != null)
        {
            v.add(new dertaggedobject(true, 1, singleextensions));
        }

        return new dersequence(v);
    }
}
