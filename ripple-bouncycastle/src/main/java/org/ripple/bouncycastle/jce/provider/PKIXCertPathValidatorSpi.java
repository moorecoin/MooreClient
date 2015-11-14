package org.ripple.bouncycastle.jce.provider;

import java.security.invalidalgorithmparameterexception;
import java.security.publickey;
import java.security.cert.certpath;
import java.security.cert.certpathparameters;
import java.security.cert.certpathvalidatorexception;
import java.security.cert.certpathvalidatorresult;
import java.security.cert.certpathvalidatorspi;
import java.security.cert.pkixcertpathchecker;
import java.security.cert.pkixcertpathvalidatorresult;
import java.security.cert.pkixparameters;
import java.security.cert.trustanchor;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.jce.exception.extcertpathvalidatorexception;
import org.ripple.bouncycastle.x509.extendedpkixparameters;

/**
 * certpathvalidatorspi implementation for x.509 certificate validation 锟?la rfc
 * 3280.
 */
public class pkixcertpathvalidatorspi
        extends certpathvalidatorspi
{

    public certpathvalidatorresult enginevalidate(
            certpath certpath,
            certpathparameters params)
            throws certpathvalidatorexception,
            invalidalgorithmparameterexception
    {
        if (!(params instanceof pkixparameters))
        {
            throw new invalidalgorithmparameterexception("parameters must be a " + pkixparameters.class.getname()
                    + " instance.");
        }

        extendedpkixparameters paramspkix;
        if (params instanceof extendedpkixparameters)
        {
            paramspkix = (extendedpkixparameters)params;
        }
        else
        {
            paramspkix = extendedpkixparameters.getinstance((pkixparameters)params);
        }
        if (paramspkix.gettrustanchors() == null)
        {
            throw new invalidalgorithmparameterexception(
                    "trustanchors is null, this is not allowed for certification path validation.");
        }

        //
        // 6.1.1 - inputs
        //

        //
        // (a)
        //
        list certs = certpath.getcertificates();
        int n = certs.size();

        if (certs.isempty())
        {
            throw new certpathvalidatorexception("certification path is empty.", null, certpath, 0);
        }

        //
        // (b)
        //
        // date validdate = certpathvalidatorutilities.getvaliddate(paramspkix);

        //
        // (c)
        //
        set userinitialpolicyset = paramspkix.getinitialpolicies();

        //
        // (d)
        // 
        trustanchor trust;
        try
        {
            trust = certpathvalidatorutilities.findtrustanchor((x509certificate) certs.get(certs.size() - 1),
                    paramspkix.gettrustanchors(), paramspkix.getsigprovider());
        }
        catch (annotatedexception e)
        {
            throw new certpathvalidatorexception(e.getmessage(), e, certpath, certs.size() - 1);
        }

        if (trust == null)
        {
            throw new certpathvalidatorexception("trust anchor for certification path not found.", null, certpath, -1);
        }

        //
        // (e), (f), (g) are part of the paramspkix object.
        //
        iterator certiter;
        int index = 0;
        int i;
        // certificate for each interation of the validation loop
        // signature information for each iteration of the validation loop
        //
        // 6.1.2 - setup
        //

        //
        // (a)
        //
        list[] policynodes = new arraylist[n + 1];
        for (int j = 0; j < policynodes.length; j++)
        {
            policynodes[j] = new arraylist();
        }

        set policyset = new hashset();

        policyset.add(rfc3280certpathutilities.any_policy);

        pkixpolicynode validpolicytree = new pkixpolicynode(new arraylist(), 0, policyset, null, new hashset(),
                rfc3280certpathutilities.any_policy, false);

        policynodes[0].add(validpolicytree);

        //
        // (b) and (c)
        //
        pkixnameconstraintvalidator nameconstraintvalidator = new pkixnameconstraintvalidator();

        // (d)
        //
        int explicitpolicy;
        set acceptablepolicies = new hashset();

        if (paramspkix.isexplicitpolicyrequired())
        {
            explicitpolicy = 0;
        }
        else
        {
            explicitpolicy = n + 1;
        }

        //
        // (e)
        //
        int inhibitanypolicy;

        if (paramspkix.isanypolicyinhibited())
        {
            inhibitanypolicy = 0;
        }
        else
        {
            inhibitanypolicy = n + 1;
        }

        //
        // (f)
        //
        int policymapping;

        if (paramspkix.ispolicymappinginhibited())
        {
            policymapping = 0;
        }
        else
        {
            policymapping = n + 1;
        }

        //
        // (g), (h), (i), (j)
        //
        publickey workingpublickey;
        x500principal workingissuername;

        x509certificate sign = trust.gettrustedcert();
        try
        {
            if (sign != null)
            {
                workingissuername = certpathvalidatorutilities.getsubjectprincipal(sign);
                workingpublickey = sign.getpublickey();
            }
            else
            {
                workingissuername = new x500principal(trust.getcaname());
                workingpublickey = trust.getcapublickey();
            }
        }
        catch (illegalargumentexception ex)
        {
            throw new extcertpathvalidatorexception("subject of trust anchor could not be (re)encoded.", ex, certpath,
                    -1);
        }

        algorithmidentifier workingalgid = null;
        try
        {
            workingalgid = certpathvalidatorutilities.getalgorithmidentifier(workingpublickey);
        }
        catch (certpathvalidatorexception e)
        {
            throw new extcertpathvalidatorexception(
                    "algorithm identifier of public key of trust anchor could not be read.", e, certpath, -1);
        }
        derobjectidentifier workingpublickeyalgorithm = workingalgid.getobjectid();
        asn1encodable workingpublickeyparameters = workingalgid.getparameters();

        //
        // (k)
        //
        int maxpathlength = n;

        //
        // 6.1.3
        //

        if (paramspkix.gettargetconstraints() != null
                && !paramspkix.gettargetconstraints().match((x509certificate) certs.get(0)))
        {
            throw new extcertpathvalidatorexception(
                    "target certificate in certification path does not match targetconstraints.", null, certpath, 0);
        }

        // 
        // initialize certpathchecker's
        //
        list pathcheckers = paramspkix.getcertpathcheckers();
        certiter = pathcheckers.iterator();
        while (certiter.hasnext())
        {
            ((pkixcertpathchecker) certiter.next()).init(false);
        }

        x509certificate cert = null;

        for (index = certs.size() - 1; index >= 0; index--)
        {
            // try
            // {
            //
            // i as defined in the algorithm description
            //
            i = n - index;

            //
            // set certificate to be checked in this round
            // sign and workingpublickey and workingissuername are set
            // at the end of the for loop and initialized the
            // first time from the trustanchor
            //
            cert = (x509certificate) certs.get(index);
            boolean verificationalreadyperformed = (index == certs.size() - 1);

            //
            // 6.1.3
            //

            rfc3280certpathutilities.processcerta(certpath, paramspkix, index, workingpublickey,
                verificationalreadyperformed, workingissuername, sign);

            rfc3280certpathutilities.processcertbc(certpath, index, nameconstraintvalidator);

            validpolicytree = rfc3280certpathutilities.processcertd(certpath, index, acceptablepolicies,
                    validpolicytree, policynodes, inhibitanypolicy);

            validpolicytree = rfc3280certpathutilities.processcerte(certpath, index, validpolicytree);

            rfc3280certpathutilities.processcertf(certpath, index, validpolicytree, explicitpolicy);

            //
            // 6.1.4
            //

            if (i != n)
            {
                if (cert != null && cert.getversion() == 1)
                {
                    throw new certpathvalidatorexception("version 1 certificates can't be used as ca ones.", null,
                            certpath, index);
                }

                rfc3280certpathutilities.preparenextcerta(certpath, index);

                validpolicytree = rfc3280certpathutilities.preparecertb(certpath, index, policynodes, validpolicytree,
                        policymapping);

                rfc3280certpathutilities.preparenextcertg(certpath, index, nameconstraintvalidator);

                // (h)
                explicitpolicy = rfc3280certpathutilities.preparenextcerth1(certpath, index, explicitpolicy);
                policymapping = rfc3280certpathutilities.preparenextcerth2(certpath, index, policymapping);
                inhibitanypolicy = rfc3280certpathutilities.preparenextcerth3(certpath, index, inhibitanypolicy);

                //
                // (i)
                //
                explicitpolicy = rfc3280certpathutilities.preparenextcerti1(certpath, index, explicitpolicy);
                policymapping = rfc3280certpathutilities.preparenextcerti2(certpath, index, policymapping);

                // (j)
                inhibitanypolicy = rfc3280certpathutilities.preparenextcertj(certpath, index, inhibitanypolicy);

                // (k)
                rfc3280certpathutilities.preparenextcertk(certpath, index);

                // (l)
                maxpathlength = rfc3280certpathutilities.preparenextcertl(certpath, index, maxpathlength);

                // (m)
                maxpathlength = rfc3280certpathutilities.preparenextcertm(certpath, index, maxpathlength);

                // (n)
                rfc3280certpathutilities.preparenextcertn(certpath, index);

                set criticalextensions = cert.getcriticalextensionoids();
                if (criticalextensions != null)
                {
                    criticalextensions = new hashset(criticalextensions);

                    // these extensions are handled by the algorithm
                    criticalextensions.remove(rfc3280certpathutilities.key_usage);
                    criticalextensions.remove(rfc3280certpathutilities.certificate_policies);
                    criticalextensions.remove(rfc3280certpathutilities.policy_mappings);
                    criticalextensions.remove(rfc3280certpathutilities.inhibit_any_policy);
                    criticalextensions.remove(rfc3280certpathutilities.issuing_distribution_point);
                    criticalextensions.remove(rfc3280certpathutilities.delta_crl_indicator);
                    criticalextensions.remove(rfc3280certpathutilities.policy_constraints);
                    criticalextensions.remove(rfc3280certpathutilities.basic_constraints);
                    criticalextensions.remove(rfc3280certpathutilities.subject_alternative_name);
                    criticalextensions.remove(rfc3280certpathutilities.name_constraints);
                }
                else
                {
                    criticalextensions = new hashset();
                }

                // (o)
                rfc3280certpathutilities.preparenextcerto(certpath, index, criticalextensions, pathcheckers);
                
                // set signing certificate for next round
                sign = cert;

                // (c)
                workingissuername = certpathvalidatorutilities.getsubjectprincipal(sign);

                // (d)
                try
                {
                    workingpublickey = certpathvalidatorutilities.getnextworkingkey(certpath.getcertificates(), index);
                }
                catch (certpathvalidatorexception e)
                {
                    throw new certpathvalidatorexception("next working key could not be retrieved.", e, certpath, index);
                }

                workingalgid = certpathvalidatorutilities.getalgorithmidentifier(workingpublickey);
                // (f)
                workingpublickeyalgorithm = workingalgid.getobjectid();
                // (e)
                workingpublickeyparameters = workingalgid.getparameters();
            }
        }

        //
        // 6.1.5 wrap-up procedure
        //

        explicitpolicy = rfc3280certpathutilities.wrapupcerta(explicitpolicy, cert);

        explicitpolicy = rfc3280certpathutilities.wrapupcertb(certpath, index + 1, explicitpolicy);

        //
        // (c) (d) and (e) are already done
        //

        //
        // (f)
        //
        set criticalextensions = cert.getcriticalextensionoids();

        if (criticalextensions != null)
        {
            criticalextensions = new hashset(criticalextensions);
            // these extensions are handled by the algorithm
            criticalextensions.remove(rfc3280certpathutilities.key_usage);
            criticalextensions.remove(rfc3280certpathutilities.certificate_policies);
            criticalextensions.remove(rfc3280certpathutilities.policy_mappings);
            criticalextensions.remove(rfc3280certpathutilities.inhibit_any_policy);
            criticalextensions.remove(rfc3280certpathutilities.issuing_distribution_point);
            criticalextensions.remove(rfc3280certpathutilities.delta_crl_indicator);
            criticalextensions.remove(rfc3280certpathutilities.policy_constraints);
            criticalextensions.remove(rfc3280certpathutilities.basic_constraints);
            criticalextensions.remove(rfc3280certpathutilities.subject_alternative_name);
            criticalextensions.remove(rfc3280certpathutilities.name_constraints);
            criticalextensions.remove(rfc3280certpathutilities.crl_distribution_points);
        }
        else
        {
            criticalextensions = new hashset();
        }

        rfc3280certpathutilities.wrapupcertf(certpath, index + 1, pathcheckers, criticalextensions);

        pkixpolicynode intersection = rfc3280certpathutilities.wrapupcertg(certpath, paramspkix, userinitialpolicyset,
                index + 1, policynodes, validpolicytree, acceptablepolicies);

        if ((explicitpolicy > 0) || (intersection != null))
        {
            return new pkixcertpathvalidatorresult(trust, intersection, cert.getpublickey());
        }

        throw new certpathvalidatorexception("path processing failed on policy.", null, certpath, index);
    }

}
