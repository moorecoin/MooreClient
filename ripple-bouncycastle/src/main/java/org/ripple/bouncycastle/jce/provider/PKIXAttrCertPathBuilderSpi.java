package org.ripple.bouncycastle.jce.provider;

import java.io.ioexception;
import java.security.invalidalgorithmparameterexception;
import java.security.principal;
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
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.jce.exception.extcertpathbuilderexception;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.x509.extendedpkixbuilderparameters;
import org.ripple.bouncycastle.x509.x509attributecertstoreselector;
import org.ripple.bouncycastle.x509.x509attributecertificate;
import org.ripple.bouncycastle.x509.x509certstoreselector;

public class pkixattrcertpathbuilderspi
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
                            + extendedpkixbuilderparameters.class.getname()
                            + ".");
        }

        extendedpkixbuilderparameters pkixparams;
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
        x509attributecertificate cert;

        // search target certificates

        selector certselect = pkixparams.gettargetconstraints();
        if (!(certselect instanceof x509attributecertstoreselector))
        {
            throw new certpathbuilderexception(
                    "targetconstraints must be an instance of "
                            + x509attributecertstoreselector.class.getname()
                            + " for "+this.getclass().getname()+" class.");
        }

        try
        {
            targets = certpathvalidatorutilities.findcertificates((x509attributecertstoreselector)certselect, pkixparams.getstores());
        }
        catch (annotatedexception e)
        {
            throw new extcertpathbuilderexception("error finding target attribute certificate.", e);
        }

        if (targets.isempty())
        {
            throw new certpathbuilderexception(
                    "no attribute certificate found matching targetcontraints.");
        }

        certpathbuilderresult result = null;

        // check all potential target certificates
        targetiter = targets.iterator();
        while (targetiter.hasnext() && result == null)
        {
            cert = (x509attributecertificate) targetiter.next();
            
            x509certstoreselector selector = new x509certstoreselector();
            principal[] principals = cert.getissuer().getprincipals();
            set issuers = new hashset();
            for (int i = 0; i < principals.length; i++)
            {
                try
                {
                    if (principals[i] instanceof x500principal)
                    {
                        selector.setsubject(((x500principal)principals[i]).getencoded());
                    }
                    issuers.addall(certpathvalidatorutilities.findcertificates(selector, pkixparams.getstores()));
                    issuers.addall(certpathvalidatorutilities.findcertificates(selector, pkixparams.getcertstores()));
                }
                catch (annotatedexception e)
                {
                    throw new extcertpathbuilderexception(
                        "public key certificate for attribute certificate cannot be searched.",
                        e);
                }
                catch (ioexception e)
                {
                    throw new extcertpathbuilderexception(
                        "cannot encode x500principal.",
                        e);
                }
            }
            if (issuers.isempty())
            {
                throw new certpathbuilderexception(
                    "public key certificate for attribute certificate cannot be found.");
            }
            iterator it = issuers.iterator();
            while (it.hasnext() && result == null)
            {
                result = build(cert, (x509certificate)it.next(), pkixparams, certpathlist);
            }
        }

        if (result == null && certpathexception != null)
        {
            throw new extcertpathbuilderexception(
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

    private certpathbuilderresult build(x509attributecertificate attrcert, x509certificate tbvcert,
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
        // chain
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
            validator = certpathvalidator.getinstance("rfc3281", bouncycastleprovider.provider_name);
        }
        catch (exception e)
        {
            // cannot happen
            throw new runtimeexception(
                            "exception creating support classes.");
        }

        try
        {
            // check whether the issuer of <tbvcert> is a trustanchor
            if (certpathvalidatorutilities.findtrustanchor(tbvcert, pkixparams.gettrustanchors(),
                pkixparams.getsigprovider()) != null)
            {
                certpath certpath;
                pkixcertpathvalidatorresult result;
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
                                            "certification path could not be validated.",
                                            e);
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
                    certpathvalidatorutilities.addadditionalstoresfromaltnames(tbvcert, pkixparams);
                }
                catch (certificateparsingexception e)
                {
                    throw new annotatedexception(
                                            "no additional x.509 stores can be added from certificate locations.",
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
                    // todo use certpathvalidatorutilities.isselfissued(issuer)?
                    // if untrusted self signed certificate continue
                    if (issuer.getissuerx500principal().equals(
                            issuer.getsubjectx500principal()))
                    {
                        continue;
                    }
                    builderresult = build(attrcert, issuer, pkixparams, tbvpath);
                }
            }
        }
        catch (annotatedexception e)
        {
            certpathexception = new annotatedexception(
                            "no valid certification path could be build.", e);
        }
        if (builderresult == null)
        {
            tbvpath.remove(tbvcert);
        }
        return builderresult;
    }

}
