package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.util.selector;

import java.io.ioexception;
import java.security.cert.certificate;
import java.security.cert.x509certselector;
import java.security.cert.x509certificate;

/**
 * this class is a selector implementation for x.509 certificates.
 * 
 * @see org.ripple.bouncycastle.util.selector
 * @see org.ripple.bouncycastle.x509.x509store
 * @see org.ripple.bouncycastle.jce.provider.x509storecertcollection
 */
public class x509certstoreselector
    extends x509certselector
    implements selector
{
    public boolean match(object obj)
    {
        if (!(obj instanceof x509certificate))
        {
            return false;
        }

        x509certificate other = (x509certificate)obj;

        return super.match(other);
    }

    public boolean match(certificate cert)
    {
        return match((object)cert);
    }

    public object clone()
    {
        x509certstoreselector selector = (x509certstoreselector)super.clone();

        return selector;
    }

    /**
     * returns an instance of this from a <code>x509certselector</code>.
     *
     * @param selector a <code>x509certselector</code> instance.
     * @return an instance of an <code>x509certstoreselector</code>.
     * @exception illegalargumentexception if selector is null or creation fails.
     */
    public static x509certstoreselector getinstance(x509certselector selector)
    {
        if (selector == null)
        {
            throw new illegalargumentexception("cannot create from null selector");
        }
        x509certstoreselector cs = new x509certstoreselector();
        cs.setauthoritykeyidentifier(selector.getauthoritykeyidentifier());
        cs.setbasicconstraints(selector.getbasicconstraints());
        cs.setcertificate(selector.getcertificate());
        cs.setcertificatevalid(selector.getcertificatevalid());
        cs.setmatchallsubjectaltnames(selector.getmatchallsubjectaltnames());
        try
        {
            cs.setpathtonames(selector.getpathtonames());
            cs.setextendedkeyusage(selector.getextendedkeyusage());
            cs.setnameconstraints(selector.getnameconstraints());
            cs.setpolicy(selector.getpolicy());
            cs.setsubjectpublickeyalgid(selector.getsubjectpublickeyalgid());
            cs.setsubjectalternativenames(selector.getsubjectalternativenames());
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("error in passed in selector: " + e);
        }
        cs.setissuer(selector.getissuer());
        cs.setkeyusage(selector.getkeyusage());
        cs.setprivatekeyvalid(selector.getprivatekeyvalid());
        cs.setserialnumber(selector.getserialnumber());
        cs.setsubject(selector.getsubject());
        cs.setsubjectkeyidentifier(selector.getsubjectkeyidentifier());
        cs.setsubjectpublickey(selector.getsubjectpublickey());
        return cs;
    }

}
