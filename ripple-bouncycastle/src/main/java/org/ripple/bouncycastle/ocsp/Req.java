package org.ripple.bouncycastle.ocsp;

import java.util.enumeration;
import java.util.hashset;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.ocsp.request;
import org.ripple.bouncycastle.asn1.x509.x509extension;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

public class req
    implements java.security.cert.x509extension
{
    private request req;

    public req(
        request req)
    {
        this.req = req;
    }

    public certificateid getcertid()
    {
        return new certificateid(req.getreqcert());
    }

    public x509extensions getsinglerequestextensions()
    {
        return x509extensions.getinstance(req.getsinglerequestextensions());
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
        if (extns != null && !extns.isempty())
        {
            return true;
        }

        return false;
    }

    private set getextensionoids(boolean critical)
    {
        set             set = new hashset();
        x509extensions  extensions = this.getsinglerequestextensions();
        
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
        x509extensions exts = this.getsinglerequestextensions();

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
