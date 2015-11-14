package org.ripple.bouncycastle.x509;

import java.io.ioexception;
import java.security.principal;
import java.security.cert.certselector;
import java.security.cert.certificate;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.list;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.attcertissuer;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.v2form;
import org.ripple.bouncycastle.jce.x509principal;
import org.ripple.bouncycastle.util.selector;

/**
 * carrying class for an attribute certificate issuer.
 * @deprecated use org.bouncycastle.cert.attributecertificateissuer
 */
public class attributecertificateissuer
    implements certselector, selector
{
    final asn1encodable form;

    /**
     * set the issuer directly with the asn.1 structure.
     * 
     * @param issuer the issuer
     */
    public attributecertificateissuer(attcertissuer issuer)
    {
        form = issuer.getissuer();
    }

    public attributecertificateissuer(x500principal principal)
        throws ioexception
    {
        this(new x509principal(principal.getencoded()));
    }

    public attributecertificateissuer(x509principal principal)
    {
        form = new v2form(generalnames.getinstance(new dersequence(new generalname(principal))));
    }

    private object[] getnames()
    {
        generalnames name;

        if (form instanceof v2form)
        {
            name = ((v2form)form).getissuername();
        }
        else
        {
            name = (generalnames)form;
        }

        generalname[] names = name.getnames();

        list l = new arraylist(names.length);

        for (int i = 0; i != names.length; i++)
        {
            if (names[i].gettagno() == generalname.directoryname)
            {
                try
                {
                    l.add(new x500principal(
                        ((asn1encodable)names[i].getname()).toasn1primitive().getencoded()));
                }
                catch (ioexception e)
                {
                    throw new runtimeexception("badly formed name object");
                }
            }
        }

        return l.toarray(new object[l.size()]);
    }

    /**
     * return any principal objects inside the attribute certificate issuer
     * object.
     * 
     * @return an array of principal objects (usually x500principal)
     */
    public principal[] getprincipals()
    {
        object[] p = this.getnames();
        list l = new arraylist();

        for (int i = 0; i != p.length; i++)
        {
            if (p[i] instanceof principal)
            {
                l.add(p[i]);
            }
        }

        return (principal[])l.toarray(new principal[l.size()]);
    }

    private boolean matchesdn(x500principal subject, generalnames targets)
    {
        generalname[] names = targets.getnames();

        for (int i = 0; i != names.length; i++)
        {
            generalname gn = names[i];

            if (gn.gettagno() == generalname.directoryname)
            {
                try
                {
                    if (new x500principal(((asn1encodable)gn.getname()).toasn1primitive().getencoded()).equals(subject))
                    {
                        return true;
                    }
                }
                catch (ioexception e)
                {
                }
            }
        }

        return false;
    }

    public object clone()
    {
        return new attributecertificateissuer(attcertissuer.getinstance(form));
    }

    public boolean match(certificate cert)
    {
        if (!(cert instanceof x509certificate))
        {
            return false;
        }

        x509certificate x509cert = (x509certificate)cert;

        if (form instanceof v2form)
        {
            v2form issuer = (v2form)form;
            if (issuer.getbasecertificateid() != null)
            {
                return issuer.getbasecertificateid().getserial().getvalue().equals(x509cert.getserialnumber())
                    && matchesdn(x509cert.getissuerx500principal(), issuer.getbasecertificateid().getissuer());
            }

            generalnames name = issuer.getissuername();
            if (matchesdn(x509cert.getsubjectx500principal(), name))
            {
                return true;
            }
        }
        else
        {
            generalnames name = (generalnames)form;
            if (matchesdn(x509cert.getsubjectx500principal(), name))
            {
                return true;
            }
        }

        return false;
    }

    public boolean equals(object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof attributecertificateissuer))
        {
            return false;
        }

        attributecertificateissuer other = (attributecertificateissuer)obj;

        return this.form.equals(other.form);
    }

    public int hashcode()
    {
        return this.form.hashcode();
    }

    public boolean match(object obj)
    {
        if (!(obj instanceof x509certificate))
        {
            return false;
        }

        return match((certificate)obj);
    }
}
