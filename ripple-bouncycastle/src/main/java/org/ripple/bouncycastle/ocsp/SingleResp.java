package org.ripple.bouncycastle.ocsp;

import java.text.parseexception;
import java.util.date;
import java.util.enumeration;
import java.util.hashset;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.ocsp.certstatus;
import org.ripple.bouncycastle.asn1.ocsp.revokedinfo;
import org.ripple.bouncycastle.asn1.ocsp.singleresponse;
import org.ripple.bouncycastle.asn1.x509.x509extension;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

public class singleresp
    implements java.security.cert.x509extension
{
    singleresponse  resp;

    public singleresp(
        singleresponse  resp)
    {
        this.resp = resp;
    }

    public certificateid getcertid()
    {
        return new certificateid(resp.getcertid());
    }

    /**
     * return the status object for the response - null indicates good.
     * 
     * @return the status object for the response, null if it is good.
     */
    public object getcertstatus()
    {
        certstatus  s = resp.getcertstatus();

        if (s.gettagno() == 0)
        {
            return null;            // good
        }
        else if (s.gettagno() == 1)
        {
            return new revokedstatus(revokedinfo.getinstance(s.getstatus()));
        }

        return new unknownstatus();
    }

    public date getthisupdate()
    {
        try
        {
            return resp.getthisupdate().getdate();
        }
        catch (parseexception e)
        {
            throw new illegalstateexception("parseexception: " + e.getmessage());
        }
    }

    /**
     * return the nextupdate value - note: this is an optional field so may
     * be returned as null.
     *
     * @return nextupdate, or null if not present.
     */
    public date getnextupdate()
    {
        if (resp.getnextupdate() == null)
        {
            return null;
        }

        try
        {
            return resp.getnextupdate().getdate();
        }
        catch (parseexception e)
        {
            throw new illegalstateexception("parseexception: " + e.getmessage());
        }
    }

    public x509extensions getsingleextensions()
    {
        return x509extensions.getinstance(resp.getsingleextensions());
    }
    
    /**
     * rfc 2650 doesn't specify any critical extensions so we return true
     * if any are encountered.
     * 
     * @return true if any critical extensions are present.
     */
    public boolean hasunsupportedcriticalextension()
    {
        set extns = getcriticalextensionoids();
        
        return extns != null && !extns.isempty();
    }

    private set getextensionoids(boolean critical)
    {
        set             set = new hashset();
        x509extensions  extensions = this.getsingleextensions();
        
        if (extensions != null)
        {
            enumeration     e = extensions.oids();
    
            while (e.hasmoreelements())
            {
                derobjectidentifier oid = (derobjectidentifier)e.nextelement();
                x509extension       ext = extensions.getextension(oid);
    
                if (critical == ext.iscritical())
                {
                    set.add(oid.getid());
                }
            }
        }

        return set;
    }

    public set getcriticalextensionoids()
    {
        return getextensionoids(true);
    }

    public set getnoncriticalextensionoids()
    {
        return getextensionoids(false);
    }

    public byte[] getextensionvalue(string oid)
    {
        x509extensions exts = this.getsingleextensions();

        if (exts != null)
        {
            x509extension   ext = exts.getextension(new derobjectidentifier(oid));

            if (ext != null)
            {
                try
                {
                    return ext.getvalue().getencoded(asn1encoding.der);
                }
                catch (exception e)
                {
                    throw new runtimeexception("error encoding " + e.tostring());
                }
            }
        }

        return null;
    }
}
