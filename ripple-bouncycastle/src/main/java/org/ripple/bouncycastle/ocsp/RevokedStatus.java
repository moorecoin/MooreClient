package org.ripple.bouncycastle.ocsp;

import java.text.parseexception;
import java.util.date;

import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.ocsp.revokedinfo;
import org.ripple.bouncycastle.asn1.x509.crlreason;

/**
 * wrapper for the revokedinfo object
 */
public class revokedstatus
    implements certificatestatus
{
    revokedinfo info;

    public revokedstatus(
        revokedinfo info)
    {
        this.info = info;
    }
    
    public revokedstatus(
        date        revocationdate,
        int         reason)
    {
        this.info = new revokedinfo(new asn1generalizedtime(revocationdate), crlreason.lookup(reason));
    }

    public date getrevocationtime()
    {
        try
        {
            return info.getrevocationtime().getdate();
        }
        catch (parseexception e)
        {
            throw new illegalstateexception("parseexception:" + e.getmessage());
        }
    }

    public boolean hasrevocationreason()
    {
        return (info.getrevocationreason() != null);
    }

    /**
     * return the revocation reason. note: this field is optional, test for it
     * with hasrevocationreason() first.
     * @return the revocation reason value.
     * @exception illegalstateexception if a reason is asked for and none is avaliable
     */
    public int getrevocationreason()
    {
        if (info.getrevocationreason() == null)
        {
            throw new illegalstateexception("attempt to get a reason where none is available");
        }

        return info.getrevocationreason().getvalue().intvalue();
    }
}
