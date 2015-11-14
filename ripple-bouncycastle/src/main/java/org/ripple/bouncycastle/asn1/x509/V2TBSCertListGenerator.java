package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1utctime;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * generator for version 2 tbscertlist structures.
 * <pre>
 *  tbscertlist  ::=  sequence  {
 *       version                 version optional,
 *                                    -- if present, shall be v2
 *       signature               algorithmidentifier,
 *       issuer                  name,
 *       thisupdate              time,
 *       nextupdate              time optional,
 *       revokedcertificates     sequence of sequence  {
 *            usercertificate         certificateserialnumber,
 *            revocationdate          time,
 *            crlentryextensions      extensions optional
 *                                          -- if present, shall be v2
 *                                 }  optional,
 *       crlextensions           [0]  explicit extensions optional
 *                                          -- if present, shall be v2
 *                                 }
 * </pre>
 *
 * <b>note: this class may be subject to change</b>
 */
public class v2tbscertlistgenerator
{
    private asn1integer         version = new asn1integer(1);
    private algorithmidentifier signature;
    private x500name            issuer;
    private time                thisupdate, nextupdate=null;
    private extensions          extensions = null;
    private asn1encodablevector crlentries = new asn1encodablevector();

    private final static asn1sequence[] reasons;

    static
    {
       reasons = new asn1sequence[11];

        reasons[0] = createreasonextension(crlreason.unspecified);
        reasons[1] = createreasonextension(crlreason.keycompromise);
        reasons[2] = createreasonextension(crlreason.cacompromise);
        reasons[3] = createreasonextension(crlreason.affiliationchanged);
        reasons[4] = createreasonextension(crlreason.superseded);
        reasons[5] = createreasonextension(crlreason.cessationofoperation);
        reasons[6] = createreasonextension(crlreason.certificatehold);
        reasons[7] = createreasonextension(7); // 7 -> unknown
        reasons[8] = createreasonextension(crlreason.removefromcrl);
        reasons[9] = createreasonextension(crlreason.privilegewithdrawn);
        reasons[10] = createreasonextension(crlreason.aacompromise);
    }

    public v2tbscertlistgenerator()
    {
    }


    public void setsignature(
        algorithmidentifier    signature)
    {
        this.signature = signature;
    }

    /**
     * @deprecated use x500name method
     */
    public void setissuer(
        x509name    issuer)
    {
        this.issuer = x500name.getinstance(issuer.toasn1primitive());
    }

    public void setissuer(x500name issuer)
    {
        this.issuer = issuer;
    }

    public void setthisupdate(
        asn1utctime thisupdate)
    {
        this.thisupdate = new time(thisupdate);
    }

    public void setnextupdate(
        asn1utctime nextupdate)
    {
        this.nextupdate = new time(nextupdate);
    }

    public void setthisupdate(
        time thisupdate)
    {
        this.thisupdate = thisupdate;
    }

    public void setnextupdate(
        time nextupdate)
    {
        this.nextupdate = nextupdate;
    }

    public void addcrlentry(
        asn1sequence crlentry)
    {
        crlentries.add(crlentry);
    }

    public void addcrlentry(asn1integer usercertificate, asn1utctime revocationdate, int reason)
    {
        addcrlentry(usercertificate, new time(revocationdate), reason);
    }

    public void addcrlentry(asn1integer usercertificate, time revocationdate, int reason)
    {
        addcrlentry(usercertificate, revocationdate, reason, null);
    }

    public void addcrlentry(asn1integer usercertificate, time revocationdate, int reason, asn1generalizedtime invaliditydate)
    {
        if (reason != 0)
        {
            asn1encodablevector v = new asn1encodablevector();

            if (reason < reasons.length)
            {
                if (reason < 0)
                {
                    throw new illegalargumentexception("invalid reason value: " + reason);
                }
                v.add(reasons[reason]);
            }
            else
            {
                v.add(createreasonextension(reason));
            }

            if (invaliditydate != null)
            {
                v.add(createinvaliditydateextension(invaliditydate));
            }

            internaladdcrlentry(usercertificate, revocationdate, new dersequence(v));
        }
        else if (invaliditydate != null)
        {
            asn1encodablevector v = new asn1encodablevector();

            v.add(createinvaliditydateextension(invaliditydate));

            internaladdcrlentry(usercertificate, revocationdate, new dersequence(v));
        }
        else
        {
            addcrlentry(usercertificate, revocationdate, null);
        }
    }

    private void internaladdcrlentry(asn1integer usercertificate, time revocationdate, asn1sequence extensions)
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(usercertificate);
        v.add(revocationdate);

        if (extensions != null)
        {
            v.add(extensions);
        }

        addcrlentry(new dersequence(v));
    }

    public void addcrlentry(asn1integer usercertificate, time revocationdate, extensions extensions)
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(usercertificate);
        v.add(revocationdate);
        
        if (extensions != null)
        {
            v.add(extensions);
        }
        
        addcrlentry(new dersequence(v));
    }

    public void setextensions(
        x509extensions    extensions)
    {
        setextensions(extensions.getinstance(extensions));
    }

    public void setextensions(
        extensions    extensions)
    {
        this.extensions = extensions;
    }

    public tbscertlist generatetbscertlist()
    {
        if ((signature == null) || (issuer == null) || (thisupdate == null))
        {
            throw new illegalstateexception("not all mandatory fields set in v2 tbscertlist generator.");
        }

        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(signature);
        v.add(issuer);

        v.add(thisupdate);
        if (nextupdate != null)
        {
            v.add(nextupdate);
        }

        // add crlentries if they exist
        if (crlentries.size() != 0)
        {
            v.add(new dersequence(crlentries));
        }

        if (extensions != null)
        {
            v.add(new dertaggedobject(0, extensions));
        }

        return new tbscertlist(new dersequence(v));
    }

    private static asn1sequence createreasonextension(int reasoncode)
    {
        asn1encodablevector v = new asn1encodablevector();

        crlreason crlreason = crlreason.lookup(reasoncode);

        try
        {
            v.add(extension.reasoncode);
            v.add(new deroctetstring(crlreason.getencoded()));
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("error encoding reason: " + e);
        }

        return new dersequence(v);
    }

    private static asn1sequence createinvaliditydateextension(asn1generalizedtime invaliditydate)
    {
        asn1encodablevector v = new asn1encodablevector();

        try
        {
            v.add(extension.invaliditydate);
            v.add(new deroctetstring(invaliditydate.getencoded()));
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("error encoding reason: " + e);
        }

        return new dersequence(v);
    }
}
