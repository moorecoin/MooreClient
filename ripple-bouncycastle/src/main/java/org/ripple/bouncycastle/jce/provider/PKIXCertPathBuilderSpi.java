package org.ripple.bouncycastle.jce.provider;

import java.security.invalidalgorithmparameterexception;
import java.security.cert.certpath;
import java.security.cert.certpathbuilderexception;
import java.security.cert.certpathbuilderresult;
import java.security.cert.certpathbuilderspi;
import java.security.cert.certpathparameters;
import java.security.cert.certpathvalidator;
import java.security.cert.certificatefactory;
import java.security.cert.certificateparsingexception;
import java.security.cert.pkixbuilderparameters;
import java.security.cert.pkixcertpathbuilderresult;
import java.security.cert.pkixcertpathvalidatorresult;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.collection;
import java.util.hashset;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.jce.exception.extcertpathbuilderexception;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.x509.extendedpkixbuilderparameters;
import org.ripple.bouncycastle.x509.x509certstoreselector;

/**
 * implements the pkix certpathbuilding algorithm for bouncycastle.
 * 
 * @see certpathbuilderspi
 */
public class pkixcertpathbuilderspi
    extends certpathbuilderspi
{
    /**
     * build and validate a certpath using the given parameter.
     * 
     * @param params pkixbuilderparameters object containing all information to
     *            build the certpath
     */
    public certpathbuilderresult enginebuild(certpathparameters params)
        throws certpathbuilderexception, invalidalgorithmparameterexception
    {
        if (!(params instanceof pkixbuilderparameters)
            && !(params instanceof extendedpkixbuilderparameters))
        {
            throw new invalidalgorithmparameterexception(
                "parameters must be an instance of "
                    + pkixbuilderparameters.class.getname() + " or "
                    + extendedpkixbuilderparameters.class.getname() + ".");
        }

        extendedpkixbuilderparameters pkixparams = null;
        if (params instanceof extendedpkixbuilderparameters)
        {
            pkixparams = (extendedpkixbuilderparameters) params;
        }
        else
        {
            pkixparams = (extendedpkixbuilderparameters) extendedpkixbuilderparameters
                .getinstance((pkixbuilderparameters) params);
        }

        collection targets;
        iterator targetiter;
        list certpathlist = new arraylist();
        x509certificate cert;

        // search target certificates

        selector certselect = pkixparams.gettargetconstraints();
        if (!(certselect instanceof x509certstoreselector))
        {
            throw new certpathbuilderexception(
                "targetconstraints must be an instance of "
                    + x509certstoreselector.class.getname() + " for "
                    + this.getclass().getname() + " class.");
        }

        try
        {
            targets = certpathvalidatorutilities.findcertificates((x509certstoreselector)certselect, pkixparams.getstores());
            targets.addall(certpathvalidatorutilities.findcertificates((x509certstoreselector)certselect, pkixparams.getcertstores()));
        }
        catch (annotatedexception e)
        {
            throw new extcertpathbuilderexception(
                "error finding target certificate.", e);
        }

        if (targets.isempty())
        {

            throw new certpathbuilderexception(
                "no certificate found matching targetcontraints.");
        }

        certpathbuilderresult result = null;

        // check all potential target certificates
        targetiter = targets.iterator();
        while (targetiter.hasnext() && result == null)
        {
            cert = (x509certificate) targetiter.next();
            result = build(cert, pkixparams, certpathlist);
        }

        if (result == null && certpathexception != null)
        {
            if (certpathexception instanceof annotatedexception)
            {
                throw new certpathbuilderexception(certpathexception.getmessage(), certpathexception.getcause());
            }
            throw new certpathbuilderexception(
                "possible certificate chain could not be validated.",
                certpathexception);
        }

        if (result == null && certpathexception == null)
        {
            throw new certpathbuilderexception(
                "unable to find certificate chain.");
        }

        return result;
    }

    private exception certpathexception;

    protected certpathbuilderresult build(x509certificate tbvcert,
        extendedpkixbuilderparameters pkixparams, list tbvpath)
    {
        // if tbvcert is readily present in tbvpath, it indicates having run
        // into a cycle in the
        // pki graph.
        if (tbvpath.contains(tbvcert))
        {
            return null;
        }
        // step out, the certificate is not allowed to appear in a certification
        // chain.
        if (pkixparams.getexcludedcerts().contains(tbvcert))
        {
            return null;
        }
        // test if certificate path exceeds maximum length
        if (pkixparams.getmaxpathlength() != -1)
        {
            if (tbvpath.size() - 1 > pkixparams.getmaxpathlength())
            {
                return null;
            }
        }

        tbvpath.add(tbvcert);

        certificatefactory cfact;
        certpathvalidator validator;
        certpathbuilderresult builderresult = null;

        try
        {
            cfact = certificatefactory.getinstance("x.509", bouncycastleprovider.provider_name);
            validator = certpathvalidator.getinstance("pkix", bouncycastleprovider.provider_name);
        }
        catch (exception e)
        {
            // cannot happen
            throw new runtimeexception("exception creating support classes.");
        }

        try
        {
            // check whether the issuer of <tbvcert> is a trustanchor
            if (certpathvalidatorutilities.findtrustanchor(tbvcert, pkixparams.gettrustanchors(),
                pkixparams.getsigprovider()) != null)
            {
                // exception message from possibly later tried certification
                // chains
                certpath certpath = null;
                pkixcertpathvalidatorresult result = null;
                try
                {
                    certpath = cfact.generatecertpath(tbvpath);
                }
                catch (exception e)
                {
                    throw new annotatedexception(
                        "certification path could not be constructed from certificate list.",
                        e);
                }

                try
                {
                    result = (pkixcertpathvalidatorresult) validator.validate(
                        certpath, pkixparams);
                }
                catch (exception e)
                {
                    throw new annotatedexception(
                        "certification path could not be validated.", e);
                }

                return new pkixcertpathbuilderresult(certpath, result
                    .gettrustanchor(), result.getpolicytree(), result
                    .getpublickey());

            }
            else
            {
                // add additional x.509 stores from locations in certificate
                try
                {
                    certpathvalidatorutilities.addadditionalstoresfromaltnames(
                        tbvcert, pkixparams);
                }
                catch (certificateparsingexception e)
                {
                    throw new annotatedexception(
                        "no additiontal x.509 stores can be added from certificate locations.",
                        e);
                }
                collection issuers = new hashset();
                // try to get the issuer certificate from one
                // of the stores
                try
                {
                    issuers.addall(certpathvalidatorutilities.findissuercerts(tbvcert, pkixparams));
                }
                catch (annotatedexception e)
                {
                    throw new annotatedexception(
                        "cannot find issuer certificate for certificate in certification path.",
                        e);
                }
                if (issuers.isempty())
                {
                    throw new annotatedexception(
                        "no issuer certificate for certificate in certification path found.");
                }
                iterator it = issuers.iterator();

                while (it.hasnext() && builderresult == null)
                {
                    x509certificate issuer = (x509certificate) it.next();
                    builderresult = build(issuer, pkixparams, tbvpath);
                }
            }
        }
        catch (annotatedexception e)
        {
            certpathexception = e;
        }
        if (builderresult == null)
        {
            tbvpath.remove(tbvcert);
        }
        return builderresult;
    }

}
