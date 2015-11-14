package org.ripple.bouncycastle.ocsp;

import java.text.parseexception;
import java.util.date;
import java.util.enumeration;
import java.util.hashset;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.ocsp.responsedata;
import org.ripple.bouncycastle.asn1.ocsp.singleresponse;
import org.ripple.bouncycastle.asn1.x509.x509extension;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

public class respdata
    implements java.security.cert.x509extension
{
    responsedata    data;

    public respdata(
        responsedata    data)
    {
        this.data = data;
    }

    public int getversion()
    {
        return data.getversion().getvalue().intvalue() + 1;
    }

    public respid getresponderid()
    {
        return new respid(data.getresponderid());
    }

    public date getproducedat()
    {
        try
        {
            return data.getproducedat().getdate();
        }
        catch (parseexception e)
        {
            throw new illegalstateexception("parseexception:" + e.getmessage());
        }
    }

    public singleresp[] getresponses()
    {
        asn1sequence    s = data.getresponses();
        singleresp[]    rs = new singleresp[s.size()];

        for (int i = 0; i != rs.length; i++)
        {
            rs[i] = new singleresp(singleresponse.getinstance(s.getobjectat(i)));
        }

        return rs;
    }

    public x509extensions getresponseextensions()
    {
        return x509extensions.getinstance(data.getresponseextensions());
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
        x509extensions  extensions = this.getresponseextensions();
        
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
        x509extensions exts = this.getresponseextensions();

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
