package org.ripple.bouncycastle.jce.provider;

import java.security.cert.certstore;
import java.security.cert.certstoreexception;
import java.security.cert.pkixparameters;
import java.security.cert.x509crl;
import java.security.cert.x509certificate;
import java.util.collection;
import java.util.date;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.set;

import org.ripple.bouncycastle.util.storeexception;
import org.ripple.bouncycastle.x509.extendedpkixparameters;
import org.ripple.bouncycastle.x509.x509crlstoreselector;
import org.ripple.bouncycastle.x509.x509store;

public class pkixcrlutil
{
    public set findcrls(x509crlstoreselector crlselect, extendedpkixparameters paramspkix, date currentdate)
        throws annotatedexception
    {
        set initialset = new hashset();

        // get complete crl(s)
        try
        {
            initialset.addall(findcrls(crlselect, paramspkix.getadditionalstores()));
            initialset.addall(findcrls(crlselect, paramspkix.getstores()));
            initialset.addall(findcrls(crlselect, paramspkix.getcertstores()));
        }
        catch (annotatedexception e)
        {
            throw new annotatedexception("exception obtaining complete crls.", e);
        }

        set finalset = new hashset();
        date validitydate = currentdate;

        if (paramspkix.getdate() != null)
        {
            validitydate = paramspkix.getdate();
        }

        // based on rfc 5280 6.3.3
        for (iterator it = initialset.iterator(); it.hasnext();)
        {
            x509crl crl = (x509crl)it.next();

            if (crl.getnextupdate().after(validitydate))
            {
                x509certificate cert = crlselect.getcertificatechecking();

                if (cert != null)
                {
                    if (crl.getthisupdate().before(cert.getnotafter()))
                    {
                        finalset.add(crl);
                    }
                }
                else
                {
                    finalset.add(crl);
                }
            }
        }

        return finalset;
    }

    public set findcrls(x509crlstoreselector crlselect, pkixparameters paramspkix)
        throws annotatedexception
    {
        set completeset = new hashset();

        // get complete crl(s)
        try
        {
            completeset.addall(findcrls(crlselect, paramspkix.getcertstores()));
        }
        catch (annotatedexception e)
        {
            throw new annotatedexception("exception obtaining complete crls.", e);
        }

        return completeset;
    }

/**
     * return a collection of all crls found in the x509store's that are
     * matching the crlselect criteriums.
     *
     * @param crlselect a {@link x509crlstoreselector} object that will be used
     *            to select the crls
     * @param crlstores a list containing only
     *            {@link org.ripple.bouncycastle.x509.x509store  x509store} objects.
     *            these are used to search for crls
     *
     * @return a collection of all found {@link java.security.cert.x509crl x509crl} objects. may be
     *         empty but never <code>null</code>.
     */
    private final collection findcrls(x509crlstoreselector crlselect,
        list crlstores) throws annotatedexception
    {
        set crls = new hashset();
        iterator iter = crlstores.iterator();

        annotatedexception lastexception = null;
        boolean foundvalidstore = false;

        while (iter.hasnext())
        {
            object obj = iter.next();

            if (obj instanceof x509store)
            {
                x509store store = (x509store)obj;

                try
                {
                    crls.addall(store.getmatches(crlselect));
                    foundvalidstore = true;
                }
                catch (storeexception e)
                {
                    lastexception = new annotatedexception(
                        "exception searching in x.509 crl store.", e);
                }
            }
            else
            {
                certstore store = (certstore)obj;

                try
                {
                    crls.addall(store.getcrls(crlselect));
                    foundvalidstore = true;
                }
                catch (certstoreexception e)
                {
                    lastexception = new annotatedexception(
                        "exception searching in x.509 crl store.", e);
                }
            }
        }
        if (!foundvalidstore && lastexception != null)
        {
            throw lastexception;
        }
        return crls;
    }

}
