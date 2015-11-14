package org.ripple.bouncycastle.jce.provider;

import java.io.ioexception;
import java.math.biginteger;
import java.security.generalsecurityexception;
import java.security.publickey;
import java.security.cert.certpath;
import java.security.cert.certpathbuilder;
import java.security.cert.certpathbuilderexception;
import java.security.cert.certpathvalidatorexception;
import java.security.cert.certificateexpiredexception;
import java.security.cert.certificatenotyetvalidexception;
import java.security.cert.pkixcertpathchecker;
import java.security.cert.x509crl;
import java.security.cert.x509certificate;
import java.security.cert.x509extension;
import java.util.arraylist;
import java.util.collection;
import java.util.date;
import java.util.enumeration;
import java.util.hashmap;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.map;
import java.util.set;
import java.util.vector;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.basicconstraints;
import org.ripple.bouncycastle.asn1.x509.crldistpoint;
import org.ripple.bouncycastle.asn1.x509.crlreason;
import org.ripple.bouncycastle.asn1.x509.distributionpoint;
import org.ripple.bouncycastle.asn1.x509.distributionpointname;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.generalsubtree;
import org.ripple.bouncycastle.asn1.x509.issuingdistributionpoint;
import org.ripple.bouncycastle.asn1.x509.nameconstraints;
import org.ripple.bouncycastle.asn1.x509.policyinformation;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.asn1.x509.x509name;
import org.ripple.bouncycastle.jce.exception.extcertpathvalidatorexception;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.x509.extendedpkixbuilderparameters;
import org.ripple.bouncycastle.x509.extendedpkixparameters;
import org.ripple.bouncycastle.x509.x509crlstoreselector;
import org.ripple.bouncycastle.x509.x509certstoreselector;

public class rfc3280certpathutilities
{
    private static final pkixcrlutil crl_util = new pkixcrlutil();

    /**
     * if the complete crl includes an issuing distribution point (idp) crl
     * extension check the following:
     * <p/>
     * (i) if the distribution point name is present in the idp crl extension
     * and the distribution field is present in the dp, then verify that one of
     * the names in the idp matches one of the names in the dp. if the
     * distribution point name is present in the idp crl extension and the
     * distribution field is omitted from the dp, then verify that one of the
     * names in the idp matches one of the names in the crlissuer field of the
     * dp.
     * </p>
     * <p/>
     * (ii) if the onlycontainsusercerts boolean is asserted in the idp crl
     * extension, verify that the certificate does not include the basic
     * constraints extension with the ca boolean asserted.
     * </p>
     * <p/>
     * (iii) if the onlycontainscacerts boolean is asserted in the idp crl
     * extension, verify that the certificate includes the basic constraints
     * extension with the ca boolean asserted.
     * </p>
     * <p/>
     * (iv) verify that the onlycontainsattributecerts boolean is not asserted.
     * </p>
     *
     * @param dp   the distribution point.
     * @param cert the certificate.
     * @param crl  the crl.
     * @throws annotatedexception if one of the conditions is not met or an error occurs.
     */
    protected static void processcrlb2(
        distributionpoint dp,
        object cert,
        x509crl crl)
        throws annotatedexception
    {
        issuingdistributionpoint idp = null;
        try
        {
            idp = issuingdistributionpoint.getinstance(certpathvalidatorutilities.getextensionvalue(crl,
                rfc3280certpathutilities.issuing_distribution_point));
        }
        catch (exception e)
        {
            throw new annotatedexception("issuing distribution point extension could not be decoded.", e);
        }
        // (b) (2) (i)
        // distribution point name is present
        if (idp != null)
        {
            if (idp.getdistributionpoint() != null)
            {
                // make list of names
                distributionpointname dpname = issuingdistributionpoint.getinstance(idp).getdistributionpoint();
                list names = new arraylist();

                if (dpname.gettype() == distributionpointname.full_name)
                {
                    generalname[] gennames = generalnames.getinstance(dpname.getname()).getnames();
                    for (int j = 0; j < gennames.length; j++)
                    {
                        names.add(gennames[j]);
                    }
                }
                if (dpname.gettype() == distributionpointname.name_relative_to_crl_issuer)
                {
                    asn1encodablevector vec = new asn1encodablevector();
                    try
                    {
                        enumeration e = asn1sequence.getinstance(
                            asn1sequence.frombytearray(certpathvalidatorutilities.getissuerprincipal(crl)
                                .getencoded())).getobjects();
                        while (e.hasmoreelements())
                        {
                            vec.add((asn1encodable)e.nextelement());
                        }
                    }
                    catch (ioexception e)
                    {
                        throw new annotatedexception("could not read crl issuer.", e);
                    }
                    vec.add(dpname.getname());
                    names.add(new generalname(x509name.getinstance(new dersequence(vec))));
                }
                boolean matches = false;
                // verify that one of the names in the idp matches one
                // of the names in the dp.
                if (dp.getdistributionpoint() != null)
                {
                    dpname = dp.getdistributionpoint();
                    generalname[] gennames = null;
                    if (dpname.gettype() == distributionpointname.full_name)
                    {
                        gennames = generalnames.getinstance(dpname.getname()).getnames();
                    }
                    if (dpname.gettype() == distributionpointname.name_relative_to_crl_issuer)
                    {
                        if (dp.getcrlissuer() != null)
                        {
                            gennames = dp.getcrlissuer().getnames();
                        }
                        else
                        {
                            gennames = new generalname[1];
                            try
                            {
                                gennames[0] = new generalname(new x509name(
                                    (asn1sequence)asn1sequence.frombytearray(certpathvalidatorutilities
                                        .getencodedissuerprincipal(cert).getencoded())));
                            }
                            catch (ioexception e)
                            {
                                throw new annotatedexception("could not read certificate issuer.", e);
                            }
                        }
                        for (int j = 0; j < gennames.length; j++)
                        {
                            enumeration e = asn1sequence.getinstance(gennames[j].getname().toasn1primitive()).getobjects();
                            asn1encodablevector vec = new asn1encodablevector();
                            while (e.hasmoreelements())
                            {
                                vec.add((asn1encodable)e.nextelement());
                            }
                            vec.add(dpname.getname());
                            gennames[j] = new generalname(new x509name(new dersequence(vec)));
                        }
                    }
                    if (gennames != null)
                    {
                        for (int j = 0; j < gennames.length; j++)
                        {
                            if (names.contains(gennames[j]))
                            {
                                matches = true;
                                break;
                            }
                        }
                    }
                    if (!matches)
                    {
                        throw new annotatedexception(
                            "no match for certificate crl issuing distribution point name to crlissuer crl distribution point.");
                    }
                }
                // verify that one of the names in
                // the idp matches one of the names in the crlissuer field of
                // the dp
                else
                {
                    if (dp.getcrlissuer() == null)
                    {
                        throw new annotatedexception("either the crlissuer or the distributionpoint field must "
                            + "be contained in distributionpoint.");
                    }
                    generalname[] gennames = dp.getcrlissuer().getnames();
                    for (int j = 0; j < gennames.length; j++)
                    {
                        if (names.contains(gennames[j]))
                        {
                            matches = true;
                            break;
                        }
                    }
                    if (!matches)
                    {
                        throw new annotatedexception(
                            "no match for certificate crl issuing distribution point name to crlissuer crl distribution point.");
                    }
                }
            }
            basicconstraints bc = null;
            try
            {
                bc = basicconstraints.getinstance(certpathvalidatorutilities.getextensionvalue((x509extension)cert,
                    basic_constraints));
            }
            catch (exception e)
            {
                throw new annotatedexception("basic constraints extension could not be decoded.", e);
            }

            if (cert instanceof x509certificate)
            {
                // (b) (2) (ii)
                if (idp.onlycontainsusercerts() && (bc != null && bc.isca()))
                {
                    throw new annotatedexception("ca cert crl only contains user certificates.");
                }

                // (b) (2) (iii)
                if (idp.onlycontainscacerts() && (bc == null || !bc.isca()))
                {
                    throw new annotatedexception("end crl only contains ca certificates.");
                }
            }

            // (b) (2) (iv)
            if (idp.onlycontainsattributecerts())
            {
                throw new annotatedexception("onlycontainsattributecerts boolean is asserted.");
            }
        }
    }

    /**
     * if the dp includes crlissuer, then verify that the issuer field in the
     * complete crl matches crlissuer in the dp and that the complete crl
     * contains an issuing distribution point extension with the indirectcrl
     * boolean asserted. otherwise, verify that the crl issuer matches the
     * certificate issuer.
     *
     * @param dp   the distribution point.
     * @param cert the certificate ot attribute certificate.
     * @param crl  the crl for <code>cert</code>.
     * @throws annotatedexception if one of the above conditions does not apply or an error
     *                            occurs.
     */
    protected static void processcrlb1(
        distributionpoint dp,
        object cert,
        x509crl crl)
        throws annotatedexception
    {
        asn1primitive idp = certpathvalidatorutilities.getextensionvalue(crl, issuing_distribution_point);
        boolean isindirect = false;
        if (idp != null)
        {
            if (issuingdistributionpoint.getinstance(idp).isindirectcrl())
            {
                isindirect = true;
            }
        }
        byte[] issuerbytes = certpathvalidatorutilities.getissuerprincipal(crl).getencoded();

        boolean matchissuer = false;
        if (dp.getcrlissuer() != null)
        {
            generalname gennames[] = dp.getcrlissuer().getnames();
            for (int j = 0; j < gennames.length; j++)
            {
                if (gennames[j].gettagno() == generalname.directoryname)
                {
                    try
                    {
                        if (arrays.areequal(gennames[j].getname().toasn1primitive().getencoded(), issuerbytes))
                        {
                            matchissuer = true;
                        }
                    }
                    catch (ioexception e)
                    {
                        throw new annotatedexception(
                            "crl issuer information from distribution point cannot be decoded.", e);
                    }
                }
            }
            if (matchissuer && !isindirect)
            {
                throw new annotatedexception("distribution point contains crlissuer field but crl is not indirect.");
            }
            if (!matchissuer)
            {
                throw new annotatedexception("crl issuer of crl does not match crl issuer of distribution point.");
            }
        }
        else
        {
            if (certpathvalidatorutilities.getissuerprincipal(crl).equals(
                certpathvalidatorutilities.getencodedissuerprincipal(cert)))
            {
                matchissuer = true;
            }
        }
        if (!matchissuer)
        {
            throw new annotatedexception("cannot find matching crl issuer for certificate.");
        }
    }

    protected static reasonsmask processcrld(
        x509crl crl,
        distributionpoint dp)
        throws annotatedexception
    {
        issuingdistributionpoint idp = null;
        try
        {
            idp = issuingdistributionpoint.getinstance(certpathvalidatorutilities.getextensionvalue(crl,
                rfc3280certpathutilities.issuing_distribution_point));
        }
        catch (exception e)
        {
            throw new annotatedexception("issuing distribution point extension could not be decoded.", e);
        }
        // (d) (1)
        if (idp != null && idp.getonlysomereasons() != null && dp.getreasons() != null)
        {
            return new reasonsmask(dp.getreasons()).intersect(new reasonsmask(idp.getonlysomereasons()));
        }
        // (d) (4)
        if ((idp == null || idp.getonlysomereasons() == null) && dp.getreasons() == null)
        {
            return reasonsmask.allreasons;
        }
        // (d) (2) and (d)(3)
        return (dp.getreasons() == null
            ? reasonsmask.allreasons
            : new reasonsmask(dp.getreasons())).intersect(idp == null
            ? reasonsmask.allreasons
            : new reasonsmask(idp.getonlysomereasons()));

    }

    public static final string certificate_policies = x509extensions.certificatepolicies.getid();

    public static final string policy_mappings = x509extensions.policymappings.getid();

    public static final string inhibit_any_policy = x509extensions.inhibitanypolicy.getid();

    public static final string issuing_distribution_point = x509extensions.issuingdistributionpoint.getid();

    public static final string freshest_crl = x509extensions.freshestcrl.getid();

    public static final string delta_crl_indicator = x509extensions.deltacrlindicator.getid();

    public static final string policy_constraints = x509extensions.policyconstraints.getid();

    public static final string basic_constraints = x509extensions.basicconstraints.getid();

    public static final string crl_distribution_points = x509extensions.crldistributionpoints.getid();

    public static final string subject_alternative_name = x509extensions.subjectalternativename.getid();

    public static final string name_constraints = x509extensions.nameconstraints.getid();

    public static final string authority_key_identifier = x509extensions.authoritykeyidentifier.getid();

    public static final string key_usage = x509extensions.keyusage.getid();

    public static final string crl_number = x509extensions.crlnumber.getid();

    public static final string any_policy = "2.5.29.32.0";

    /*
     * key usage bits
     */
    protected static final int key_cert_sign = 5;

    protected static final int crl_sign = 6;

    /**
     * obtain and validate the certification path for the complete crl issuer.
     * if a key usage extension is present in the crl issuer's certificate,
     * verify that the crlsign bit is set.
     *
     * @param crl                crl which contains revocation information for the certificate
     *                           <code>cert</code>.
     * @param cert               the attribute certificate or certificate to check if it is
     *                           revoked.
     * @param defaultcrlsigncert the issuer certificate of the certificate <code>cert</code>.
     * @param defaultcrlsignkey  the public key of the issuer certificate
     *                           <code>defaultcrlsigncert</code>.
     * @param paramspkix         paramspkix pkix parameters.
     * @param certpathcerts      the certificates on the certification path.
     * @return a <code>set</code> with all keys of possible crl issuer
     *         certificates.
     * @throws annotatedexception if the crl is not valid or the status cannot be checked or
     *                            some error occurs.
     */
    protected static set processcrlf(
        x509crl crl,
        object cert,
        x509certificate defaultcrlsigncert,
        publickey defaultcrlsignkey,
        extendedpkixparameters paramspkix,
        list certpathcerts)
        throws annotatedexception
    {
        // (f)

        // get issuer from crl
        x509certstoreselector selector = new x509certstoreselector();
        try
        {
            byte[] issuerprincipal = certpathvalidatorutilities.getissuerprincipal(crl).getencoded();
            selector.setsubject(issuerprincipal);
        }
        catch (ioexception e)
        {
            throw new annotatedexception(
                "subject criteria for certificate selector to find issuer certificate for crl could not be set.", e);
        }

        // get crl signing certs
        collection coll;
        try
        {
            coll = certpathvalidatorutilities.findcertificates(selector, paramspkix.getstores());
            coll.addall(certpathvalidatorutilities.findcertificates(selector, paramspkix.getadditionalstores()));
            coll.addall(certpathvalidatorutilities.findcertificates(selector, paramspkix.getcertstores()));
        }
        catch (annotatedexception e)
        {
            throw new annotatedexception("issuer certificate for crl cannot be searched.", e);
        }

        coll.add(defaultcrlsigncert);

        iterator cert_it = coll.iterator();

        list validcerts = new arraylist();
        list validkeys = new arraylist();

        while (cert_it.hasnext())
        {
            x509certificate signingcert = (x509certificate)cert_it.next();

            /*
             * ca of the certificate, for which this crl is checked, has also
             * signed crl, so skip the path validation, because is already done
             */
            if (signingcert.equals(defaultcrlsigncert))
            {
                validcerts.add(signingcert);
                validkeys.add(defaultcrlsignkey);
                continue;
            }
            try
            {
                certpathbuilder builder = certpathbuilder.getinstance("pkix", bouncycastleprovider.provider_name);
                selector = new x509certstoreselector();
                selector.setcertificate(signingcert);
                extendedpkixparameters temp = (extendedpkixparameters)paramspkix.clone();
                temp.settargetcertconstraints(selector);
                extendedpkixbuilderparameters params = (extendedpkixbuilderparameters)extendedpkixbuilderparameters
                    .getinstance(temp);
                /*
                 * if signingcert is placed not higher on the cert path a
                 * dependency loop results. crl for cert is checked, but
                 * signingcert is needed for checking the crl which is dependent
                 * on checking cert because it is higher in the cert path and so
                 * signing signingcert transitively. so, revocation is disabled,
                 * forgery attacks of the crl are detected in this outer loop
                 * for all other it must be enabled to prevent forgery attacks
                 */
                if (certpathcerts.contains(signingcert))
                {
                    params.setrevocationenabled(false);
                }
                else
                {
                    params.setrevocationenabled(true);
                }
                list certs = builder.build(params).getcertpath().getcertificates();
                validcerts.add(signingcert);
                validkeys.add(certpathvalidatorutilities.getnextworkingkey(certs, 0));
            }
            catch (certpathbuilderexception e)
            {
                throw new annotatedexception("internal error.", e);
            }
            catch (certpathvalidatorexception e)
            {
                throw new annotatedexception("public key of issuer certificate of crl could not be retrieved.", e);
            }
            catch (exception e)
            {
                throw new runtimeexception(e.getmessage());
            }
        }

        set checkkeys = new hashset();

        annotatedexception lastexception = null;
        for (int i = 0; i < validcerts.size(); i++)
        {
            x509certificate signcert = (x509certificate)validcerts.get(i);
            boolean[] keyusage = signcert.getkeyusage();

            if (keyusage != null && (keyusage.length < 7 || !keyusage[crl_sign]))
            {
                lastexception = new annotatedexception(
                    "issuer certificate key usage extension does not permit crl signing.");
            }
            else
            {
                checkkeys.add(validkeys.get(i));
            }
        }

        if (checkkeys.isempty() && lastexception == null)
        {
            throw new annotatedexception("cannot find a valid issuer certificate.");
        }
        if (checkkeys.isempty() && lastexception != null)
        {
            throw lastexception;
        }

        return checkkeys;
    }

    protected static publickey processcrlg(
        x509crl crl,
        set keys)
        throws annotatedexception
    {
        exception lastexception = null;
        for (iterator it = keys.iterator(); it.hasnext();)
        {
            publickey key = (publickey)it.next();
            try
            {
                crl.verify(key);
                return key;
            }
            catch (exception e)
            {
                lastexception = e;
            }
        }
        throw new annotatedexception("cannot verify crl.", lastexception);
    }

    protected static x509crl processcrlh(
        set deltacrls,
        publickey key)
        throws annotatedexception
    {
        exception lastexception = null;

        for (iterator it = deltacrls.iterator(); it.hasnext();)
        {
            x509crl crl = (x509crl)it.next();
            try
            {
                crl.verify(key);
                return crl;
            }
            catch (exception e)
            {
                lastexception = e;
            }
        }

        if (lastexception != null)
        {
            throw new annotatedexception("cannot verify delta crl.", lastexception);
        }
        return null;
    }

    protected static set processcrla1i(
        date currentdate,
        extendedpkixparameters paramspkix,
        x509certificate cert,
        x509crl crl)
        throws annotatedexception
    {
        set set = new hashset();
        if (paramspkix.isusedeltasenabled())
        {
            crldistpoint freshestcrl = null;
            try
            {
                freshestcrl = crldistpoint
                    .getinstance(certpathvalidatorutilities.getextensionvalue(cert, freshest_crl));
            }
            catch (annotatedexception e)
            {
                throw new annotatedexception("freshest crl extension could not be decoded from certificate.", e);
            }
            if (freshestcrl == null)
            {
                try
                {
                    freshestcrl = crldistpoint.getinstance(certpathvalidatorutilities.getextensionvalue(crl,
                        freshest_crl));
                }
                catch (annotatedexception e)
                {
                    throw new annotatedexception("freshest crl extension could not be decoded from crl.", e);
                }
            }
            if (freshestcrl != null)
            {
                try
                {
                    certpathvalidatorutilities.addadditionalstoresfromcrldistributionpoint(freshestcrl, paramspkix);
                }
                catch (annotatedexception e)
                {
                    throw new annotatedexception(
                        "no new delta crl locations could be added from freshest crl extension.", e);
                }
                // get delta crl(s)
                try
                {
                    set.addall(certpathvalidatorutilities.getdeltacrls(currentdate, paramspkix, crl));
                }
                catch (annotatedexception e)
                {
                    throw new annotatedexception("exception obtaining delta crls.", e);
                }
            }
        }
        return set;
    }

    protected static set[] processcrla1ii(
        date currentdate,
        extendedpkixparameters paramspkix,
        x509certificate cert,
        x509crl crl)
        throws annotatedexception
    {
        set deltaset = new hashset();
        x509crlstoreselector crlselect = new x509crlstoreselector();
        crlselect.setcertificatechecking(cert);

        try
        {
            crlselect.addissuername(crl.getissuerx500principal().getencoded());
        }
        catch (ioexception e)
        {
            throw new annotatedexception("cannot extract issuer from crl." + e, e);
        }

        crlselect.setcompletecrlenabled(true);
        set completeset = crl_util.findcrls(crlselect, paramspkix, currentdate);

        if (paramspkix.isusedeltasenabled())
        {
            // get delta crl(s)
            try
            {
                deltaset.addall(certpathvalidatorutilities.getdeltacrls(currentdate, paramspkix, crl));
            }
            catch (annotatedexception e)
            {
                throw new annotatedexception("exception obtaining delta crls.", e);
            }
        }
        return new set[]
            {
                completeset,
                deltaset};
    }



    /**
     * if use-deltas is set, verify the issuer and scope of the delta crl.
     *
     * @param deltacrl    the delta crl.
     * @param completecrl the complete crl.
     * @param pkixparams  the pkix paramaters.
     * @throws annotatedexception if an exception occurs.
     */
    protected static void processcrlc(
        x509crl deltacrl,
        x509crl completecrl,
        extendedpkixparameters pkixparams)
        throws annotatedexception
    {
        if (deltacrl == null)
        {
            return;
        }
        issuingdistributionpoint completeidp = null;
        try
        {
            completeidp = issuingdistributionpoint.getinstance(certpathvalidatorutilities.getextensionvalue(
                completecrl, rfc3280certpathutilities.issuing_distribution_point));
        }
        catch (exception e)
        {
            throw new annotatedexception("issuing distribution point extension could not be decoded.", e);
        }

        if (pkixparams.isusedeltasenabled())
        {
            // (c) (1)
            if (!deltacrl.getissuerx500principal().equals(completecrl.getissuerx500principal()))
            {
                throw new annotatedexception("complete crl issuer does not match delta crl issuer.");
            }

            // (c) (2)
            issuingdistributionpoint deltaidp = null;
            try
            {
                deltaidp = issuingdistributionpoint.getinstance(certpathvalidatorutilities.getextensionvalue(
                    deltacrl, issuing_distribution_point));
            }
            catch (exception e)
            {
                throw new annotatedexception(
                    "issuing distribution point extension from delta crl could not be decoded.", e);
            }

            boolean match = false;
            if (completeidp == null)
            {
                if (deltaidp == null)
                {
                    match = true;
                }
            }
            else
            {
                if (completeidp.equals(deltaidp))
                {
                    match = true;
                }
            }
            if (!match)
            {
                throw new annotatedexception(
                    "issuing distribution point extension from delta crl and complete crl does not match.");
            }

            // (c) (3)
            asn1primitive completekeyidentifier = null;
            try
            {
                completekeyidentifier = certpathvalidatorutilities.getextensionvalue(
                    completecrl, authority_key_identifier);
            }
            catch (annotatedexception e)
            {
                throw new annotatedexception(
                    "authority key identifier extension could not be extracted from complete crl.", e);
            }

            asn1primitive deltakeyidentifier = null;
            try
            {
                deltakeyidentifier = certpathvalidatorutilities.getextensionvalue(
                    deltacrl, authority_key_identifier);
            }
            catch (annotatedexception e)
            {
                throw new annotatedexception(
                    "authority key identifier extension could not be extracted from delta crl.", e);
            }

            if (completekeyidentifier == null)
            {
                throw new annotatedexception("crl authority key identifier is null.");
            }

            if (deltakeyidentifier == null)
            {
                throw new annotatedexception("delta crl authority key identifier is null.");
            }

            if (!completekeyidentifier.equals(deltakeyidentifier))
            {
                throw new annotatedexception(
                    "delta crl authority key identifier does not match complete crl authority key identifier.");
            }
        }
    }

    protected static void processcrli(
        date validdate,
        x509crl deltacrl,
        object cert,
        certstatus certstatus,
        extendedpkixparameters pkixparams)
        throws annotatedexception
    {
        if (pkixparams.isusedeltasenabled() && deltacrl != null)
        {
            certpathvalidatorutilities.getcertstatus(validdate, deltacrl, cert, certstatus);
        }
    }

    protected static void processcrlj(
        date validdate,
        x509crl completecrl,
        object cert,
        certstatus certstatus)
        throws annotatedexception
    {
        if (certstatus.getcertstatus() == certstatus.unrevoked)
        {
            certpathvalidatorutilities.getcertstatus(validdate, completecrl, cert, certstatus);
        }
    }

    protected static pkixpolicynode preparecertb(
        certpath certpath,
        int index,
        list[] policynodes,
        pkixpolicynode validpolicytree,
        int policymapping)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        int n = certs.size();
        // i as defined in the algorithm description
        int i = n - index;
        // (b)
        //
        asn1sequence pm = null;
        try
        {
            pm = dersequence.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.policy_mappings));
        }
        catch (annotatedexception ex)
        {
            throw new extcertpathvalidatorexception("policy mappings extension could not be decoded.", ex, certpath,
                index);
        }
        pkixpolicynode _validpolicytree = validpolicytree;
        if (pm != null)
        {
            asn1sequence mappings = (asn1sequence)pm;
            map m_idp = new hashmap();
            set s_idp = new hashset();

            for (int j = 0; j < mappings.size(); j++)
            {
                asn1sequence mapping = (asn1sequence)mappings.getobjectat(j);
                string id_p = ((derobjectidentifier)mapping.getobjectat(0)).getid();
                string sd_p = ((derobjectidentifier)mapping.getobjectat(1)).getid();
                set tmp;

                if (!m_idp.containskey(id_p))
                {
                    tmp = new hashset();
                    tmp.add(sd_p);
                    m_idp.put(id_p, tmp);
                    s_idp.add(id_p);
                }
                else
                {
                    tmp = (set)m_idp.get(id_p);
                    tmp.add(sd_p);
                }
            }

            iterator it_idp = s_idp.iterator();
            while (it_idp.hasnext())
            {
                string id_p = (string)it_idp.next();

                //
                // (1)
                //
                if (policymapping > 0)
                {
                    boolean idp_found = false;
                    iterator nodes_i = policynodes[i].iterator();
                    while (nodes_i.hasnext())
                    {
                        pkixpolicynode node = (pkixpolicynode)nodes_i.next();
                        if (node.getvalidpolicy().equals(id_p))
                        {
                            idp_found = true;
                            node.expectedpolicies = (set)m_idp.get(id_p);
                            break;
                        }
                    }

                    if (!idp_found)
                    {
                        nodes_i = policynodes[i].iterator();
                        while (nodes_i.hasnext())
                        {
                            pkixpolicynode node = (pkixpolicynode)nodes_i.next();
                            if (rfc3280certpathutilities.any_policy.equals(node.getvalidpolicy()))
                            {
                                set pq = null;
                                asn1sequence policies = null;
                                try
                                {
                                    policies = (asn1sequence)certpathvalidatorutilities.getextensionvalue(cert,
                                        rfc3280certpathutilities.certificate_policies);
                                }
                                catch (annotatedexception e)
                                {
                                    throw new extcertpathvalidatorexception(
                                        "certificate policies extension could not be decoded.", e, certpath, index);
                                }
                                enumeration e = policies.getobjects();
                                while (e.hasmoreelements())
                                {
                                    policyinformation pinfo = null;
                                    try
                                    {
                                        pinfo = policyinformation.getinstance(e.nextelement());
                                    }
                                    catch (exception ex)
                                    {
                                        throw new certpathvalidatorexception(
                                            "policy information could not be decoded.", ex, certpath, index);
                                    }
                                    if (rfc3280certpathutilities.any_policy.equals(pinfo.getpolicyidentifier().getid()))
                                    {
                                        try
                                        {
                                            pq = certpathvalidatorutilities
                                                .getqualifierset(pinfo.getpolicyqualifiers());
                                        }
                                        catch (certpathvalidatorexception ex)
                                        {

                                            throw new extcertpathvalidatorexception(
                                                "policy qualifier info set could not be decoded.", ex, certpath,
                                                index);
                                        }
                                        break;
                                    }
                                }
                                boolean ci = false;
                                if (cert.getcriticalextensionoids() != null)
                                {
                                    ci = cert.getcriticalextensionoids().contains(
                                        rfc3280certpathutilities.certificate_policies);
                                }

                                pkixpolicynode p_node = (pkixpolicynode)node.getparent();
                                if (rfc3280certpathutilities.any_policy.equals(p_node.getvalidpolicy()))
                                {
                                    pkixpolicynode c_node = new pkixpolicynode(new arraylist(), i, (set)m_idp
                                        .get(id_p), p_node, pq, id_p, ci);
                                    p_node.addchild(c_node);
                                    policynodes[i].add(c_node);
                                }
                                break;
                            }
                        }
                    }

                    //
                    // (2)
                    //
                }
                else if (policymapping <= 0)
                {
                    iterator nodes_i = policynodes[i].iterator();
                    while (nodes_i.hasnext())
                    {
                        pkixpolicynode node = (pkixpolicynode)nodes_i.next();
                        if (node.getvalidpolicy().equals(id_p))
                        {
                            pkixpolicynode p_node = (pkixpolicynode)node.getparent();
                            p_node.removechild(node);
                            nodes_i.remove();
                            for (int k = (i - 1); k >= 0; k--)
                            {
                                list nodes = policynodes[k];
                                for (int l = 0; l < nodes.size(); l++)
                                {
                                    pkixpolicynode node2 = (pkixpolicynode)nodes.get(l);
                                    if (!node2.haschildren())
                                    {
                                        _validpolicytree = certpathvalidatorutilities.removepolicynode(
                                            _validpolicytree, policynodes, node2);
                                        if (_validpolicytree == null)
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return _validpolicytree;
    }

    protected static void preparenextcerta(
        certpath certpath,
        int index)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        //
        // (a) check the policy mappings
        //
        asn1sequence pm = null;
        try
        {
            pm = dersequence.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.policy_mappings));
        }
        catch (annotatedexception ex)
        {
            throw new extcertpathvalidatorexception("policy mappings extension could not be decoded.", ex, certpath,
                index);
        }
        if (pm != null)
        {
            asn1sequence mappings = pm;

            for (int j = 0; j < mappings.size(); j++)
            {
                derobjectidentifier issuerdomainpolicy = null;
                derobjectidentifier subjectdomainpolicy = null;
                try
                {
                    asn1sequence mapping = dersequence.getinstance(mappings.getobjectat(j));

                    issuerdomainpolicy = derobjectidentifier.getinstance(mapping.getobjectat(0));
                    subjectdomainpolicy = derobjectidentifier.getinstance(mapping.getobjectat(1));
                }
                catch (exception e)
                {
                    throw new extcertpathvalidatorexception("policy mappings extension contents could not be decoded.",
                        e, certpath, index);
                }

                if (rfc3280certpathutilities.any_policy.equals(issuerdomainpolicy.getid()))
                {

                    throw new certpathvalidatorexception("issuerdomainpolicy is anypolicy", null, certpath, index);
                }

                if (rfc3280certpathutilities.any_policy.equals(subjectdomainpolicy.getid()))
                {

                    throw new certpathvalidatorexception("subjectdomainpolicy is anypolicy,", null, certpath, index);
                }
            }
        }
    }

    protected static void processcertf(
        certpath certpath,
        int index,
        pkixpolicynode validpolicytree,
        int explicitpolicy)
        throws certpathvalidatorexception
    {
        //
        // (f)
        //
        if (explicitpolicy <= 0 && validpolicytree == null)
        {
            throw new extcertpathvalidatorexception("no valid policy tree found when one expected.", null, certpath,
                index);
        }
    }

    protected static pkixpolicynode processcerte(
        certpath certpath,
        int index,
        pkixpolicynode validpolicytree)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        // 
        // (e)
        //
        asn1sequence certpolicies = null;
        try
        {
            certpolicies = dersequence.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.certificate_policies));
        }
        catch (annotatedexception e)
        {
            throw new extcertpathvalidatorexception("could not read certificate policies extension from certificate.",
                e, certpath, index);
        }
        if (certpolicies == null)
        {
            validpolicytree = null;
        }
        return validpolicytree;
    }

    protected static void processcertbc(
        certpath certpath,
        int index,
        pkixnameconstraintvalidator nameconstraintvalidator)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        int n = certs.size();
        // i as defined in the algorithm description
        int i = n - index;
        //
        // (b), (c) permitted and excluded subtree checking.
        //
        if (!(certpathvalidatorutilities.isselfissued(cert) && (i < n)))
        {
            x500principal principal = certpathvalidatorutilities.getsubjectprincipal(cert);
            asn1inputstream ain = new asn1inputstream(principal.getencoded());
            asn1sequence dns;

            try
            {
                dns = dersequence.getinstance(ain.readobject());
            }
            catch (exception e)
            {
                throw new certpathvalidatorexception("exception extracting subject name when checking subtrees.", e,
                    certpath, index);
            }

            try
            {
                nameconstraintvalidator.checkpermitteddn(dns);
                nameconstraintvalidator.checkexcludeddn(dns);
            }
            catch (pkixnameconstraintvalidatorexception e)
            {
                throw new certpathvalidatorexception("subtree check for certificate subject failed.", e, certpath,
                    index);
            }

            generalnames altname = null;
            try
            {
                altname = generalnames.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                    rfc3280certpathutilities.subject_alternative_name));
            }
            catch (exception e)
            {
                throw new certpathvalidatorexception("subject alternative name extension could not be decoded.", e,
                    certpath, index);
            }
            vector emails = new x509name(dns).getvalues(x509name.emailaddress);
            for (enumeration e = emails.elements(); e.hasmoreelements();)
            {
                string email = (string)e.nextelement();
                generalname emailasgeneralname = new generalname(generalname.rfc822name, email);
                try
                {
                    nameconstraintvalidator.checkpermitted(emailasgeneralname);
                    nameconstraintvalidator.checkexcluded(emailasgeneralname);
                }
                catch (pkixnameconstraintvalidatorexception ex)
                {
                    throw new certpathvalidatorexception(
                        "subtree check for certificate subject alternative email failed.", ex, certpath, index);
                }
            }
            if (altname != null)
            {
                generalname[] gennames = null;
                try
                {
                    gennames = altname.getnames();
                }
                catch (exception e)
                {
                    throw new certpathvalidatorexception("subject alternative name contents could not be decoded.", e,
                        certpath, index);
                }
                for (int j = 0; j < gennames.length; j++)
                {

                    try
                    {
                        nameconstraintvalidator.checkpermitted(gennames[j]);
                        nameconstraintvalidator.checkexcluded(gennames[j]);
                    }
                    catch (pkixnameconstraintvalidatorexception e)
                    {
                        throw new certpathvalidatorexception(
                            "subtree check for certificate subject alternative name failed.", e, certpath, index);
                    }
                }
            }
        }
    }

    protected static pkixpolicynode processcertd(
        certpath certpath,
        int index,
        set acceptablepolicies,
        pkixpolicynode validpolicytree,
        list[] policynodes,
        int inhibitanypolicy)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        int n = certs.size();
        // i as defined in the algorithm description
        int i = n - index;
        //
        // (d) policy information checking against initial policy and
        // policy mapping
        //
        asn1sequence certpolicies = null;
        try
        {
            certpolicies = dersequence.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.certificate_policies));
        }
        catch (annotatedexception e)
        {
            throw new extcertpathvalidatorexception("could not read certificate policies extension from certificate.",
                e, certpath, index);
        }
        if (certpolicies != null && validpolicytree != null)
        {
            //
            // (d) (1)
            //
            enumeration e = certpolicies.getobjects();
            set pols = new hashset();

            while (e.hasmoreelements())
            {
                policyinformation pinfo = policyinformation.getinstance(e.nextelement());
                derobjectidentifier poid = pinfo.getpolicyidentifier();

                pols.add(poid.getid());

                if (!rfc3280certpathutilities.any_policy.equals(poid.getid()))
                {
                    set pq = null;
                    try
                    {
                        pq = certpathvalidatorutilities.getqualifierset(pinfo.getpolicyqualifiers());
                    }
                    catch (certpathvalidatorexception ex)
                    {
                        throw new extcertpathvalidatorexception("policy qualifier info set could not be build.", ex,
                            certpath, index);
                    }

                    boolean match = certpathvalidatorutilities.processcertd1i(i, policynodes, poid, pq);

                    if (!match)
                    {
                        certpathvalidatorutilities.processcertd1ii(i, policynodes, poid, pq);
                    }
                }
            }

            if (acceptablepolicies.isempty() || acceptablepolicies.contains(rfc3280certpathutilities.any_policy))
            {
                acceptablepolicies.clear();
                acceptablepolicies.addall(pols);
            }
            else
            {
                iterator it = acceptablepolicies.iterator();
                set t1 = new hashset();

                while (it.hasnext())
                {
                    object o = it.next();

                    if (pols.contains(o))
                    {
                        t1.add(o);
                    }
                }
                acceptablepolicies.clear();
                acceptablepolicies.addall(t1);
            }

            //
            // (d) (2)
            //
            if ((inhibitanypolicy > 0) || ((i < n) && certpathvalidatorutilities.isselfissued(cert)))
            {
                e = certpolicies.getobjects();

                while (e.hasmoreelements())
                {
                    policyinformation pinfo = policyinformation.getinstance(e.nextelement());

                    if (rfc3280certpathutilities.any_policy.equals(pinfo.getpolicyidentifier().getid()))
                    {
                        set _apq = certpathvalidatorutilities.getqualifierset(pinfo.getpolicyqualifiers());
                        list _nodes = policynodes[i - 1];

                        for (int k = 0; k < _nodes.size(); k++)
                        {
                            pkixpolicynode _node = (pkixpolicynode)_nodes.get(k);

                            iterator _policysetiter = _node.getexpectedpolicies().iterator();
                            while (_policysetiter.hasnext())
                            {
                                object _tmp = _policysetiter.next();

                                string _policy;
                                if (_tmp instanceof string)
                                {
                                    _policy = (string)_tmp;
                                }
                                else if (_tmp instanceof derobjectidentifier)
                                {
                                    _policy = ((derobjectidentifier)_tmp).getid();
                                }
                                else
                                {
                                    continue;
                                }

                                boolean _found = false;
                                iterator _childreniter = _node.getchildren();

                                while (_childreniter.hasnext())
                                {
                                    pkixpolicynode _child = (pkixpolicynode)_childreniter.next();

                                    if (_policy.equals(_child.getvalidpolicy()))
                                    {
                                        _found = true;
                                    }
                                }

                                if (!_found)
                                {
                                    set _newchildexpectedpolicies = new hashset();
                                    _newchildexpectedpolicies.add(_policy);

                                    pkixpolicynode _newchild = new pkixpolicynode(new arraylist(), i,
                                        _newchildexpectedpolicies, _node, _apq, _policy, false);
                                    _node.addchild(_newchild);
                                    policynodes[i].add(_newchild);
                                }
                            }
                        }
                        break;
                    }
                }
            }

            pkixpolicynode _validpolicytree = validpolicytree;
            //
            // (d) (3)
            //
            for (int j = (i - 1); j >= 0; j--)
            {
                list nodes = policynodes[j];

                for (int k = 0; k < nodes.size(); k++)
                {
                    pkixpolicynode node = (pkixpolicynode)nodes.get(k);
                    if (!node.haschildren())
                    {
                        _validpolicytree = certpathvalidatorutilities.removepolicynode(_validpolicytree, policynodes,
                            node);
                        if (_validpolicytree == null)
                        {
                            break;
                        }
                    }
                }
            }

            //
            // d (4)
            //
            set criticalextensionoids = cert.getcriticalextensionoids();

            if (criticalextensionoids != null)
            {
                boolean critical = criticalextensionoids.contains(rfc3280certpathutilities.certificate_policies);

                list nodes = policynodes[i];
                for (int j = 0; j < nodes.size(); j++)
                {
                    pkixpolicynode node = (pkixpolicynode)nodes.get(j);
                    node.setcritical(critical);
                }
            }
            return _validpolicytree;
        }
        return null;
    }

    protected static void processcerta(
        certpath certpath,
        extendedpkixparameters paramspkix,
        int index,
        publickey workingpublickey,
        boolean verificationalreadyperformed,
        x500principal workingissuername,
        x509certificate sign)
        throws extcertpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (a) verify
        //
        if (!verificationalreadyperformed)
        {
            try
            {
                // (a) (1)
                //
                certpathvalidatorutilities.verifyx509certificate(cert, workingpublickey,
                    paramspkix.getsigprovider());
            }
            catch (generalsecurityexception e)
            {
                throw new extcertpathvalidatorexception("could not validate certificate signature.", e, certpath, index);
            }
        }

        try
        {
            // (a) (2)
            //
            cert.checkvalidity(certpathvalidatorutilities
                .getvalidcertdatefromvaliditymodel(paramspkix, certpath, index));
        }
        catch (certificateexpiredexception e)
        {
            throw new extcertpathvalidatorexception("could not validate certificate: " + e.getmessage(), e, certpath, index);
        }
        catch (certificatenotyetvalidexception e)
        {
            throw new extcertpathvalidatorexception("could not validate certificate: " + e.getmessage(), e, certpath, index);
        }
        catch (annotatedexception e)
        {
            throw new extcertpathvalidatorexception("could not validate time of certificate.", e, certpath, index);
        }

        //
        // (a) (3)
        //
        if (paramspkix.isrevocationenabled())
        {
            try
            {
                checkcrls(paramspkix, cert, certpathvalidatorutilities.getvalidcertdatefromvaliditymodel(paramspkix,
                    certpath, index), sign, workingpublickey, certs);
            }
            catch (annotatedexception e)
            {
                throwable cause = e;
                if (null != e.getcause())
                {
                    cause = e.getcause();
                }
                throw new extcertpathvalidatorexception(e.getmessage(), cause, certpath, index);
            }
        }

        //
        // (a) (4) name chaining
        //
        if (!certpathvalidatorutilities.getencodedissuerprincipal(cert).equals(workingissuername))
        {
            throw new extcertpathvalidatorexception("issuername(" + certpathvalidatorutilities.getencodedissuerprincipal(cert)
                + ") does not match subjectname(" + workingissuername + ") of signing certificate.", null,
                certpath, index);
        }
    }

    protected static int preparenextcerti1(
        certpath certpath,
        int index,
        int explicitpolicy)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (i)
        //
        asn1sequence pc = null;
        try
        {
            pc = dersequence.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.policy_constraints));
        }
        catch (exception e)
        {
            throw new extcertpathvalidatorexception("policy constraints extension cannot be decoded.", e, certpath,
                index);
        }

        int tmpint;

        if (pc != null)
        {
            enumeration policyconstraints = pc.getobjects();

            while (policyconstraints.hasmoreelements())
            {
                try
                {

                    asn1taggedobject constraint = asn1taggedobject.getinstance(policyconstraints.nextelement());
                    if (constraint.gettagno() == 0)
                    {
                        tmpint = derinteger.getinstance(constraint, false).getvalue().intvalue();
                        if (tmpint < explicitpolicy)
                        {
                            return tmpint;
                        }
                        break;
                    }
                }
                catch (illegalargumentexception e)
                {
                    throw new extcertpathvalidatorexception("policy constraints extension contents cannot be decoded.",
                        e, certpath, index);
                }
            }
        }
        return explicitpolicy;
    }

    protected static int preparenextcerti2(
        certpath certpath,
        int index,
        int policymapping)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (i)
        //
        asn1sequence pc = null;
        try
        {
            pc = dersequence.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.policy_constraints));
        }
        catch (exception e)
        {
            throw new extcertpathvalidatorexception("policy constraints extension cannot be decoded.", e, certpath,
                index);
        }

        int tmpint;

        if (pc != null)
        {
            enumeration policyconstraints = pc.getobjects();

            while (policyconstraints.hasmoreelements())
            {
                try
                {
                    asn1taggedobject constraint = asn1taggedobject.getinstance(policyconstraints.nextelement());
                    if (constraint.gettagno() == 1)
                    {
                        tmpint = derinteger.getinstance(constraint, false).getvalue().intvalue();
                        if (tmpint < policymapping)
                        {
                            return tmpint;
                        }
                        break;
                    }
                }
                catch (illegalargumentexception e)
                {
                    throw new extcertpathvalidatorexception("policy constraints extension contents cannot be decoded.",
                        e, certpath, index);
                }
            }
        }
        return policymapping;
    }

    protected static void preparenextcertg(
        certpath certpath,
        int index,
        pkixnameconstraintvalidator nameconstraintvalidator)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (g) handle the name constraints extension
        //
        nameconstraints nc = null;
        try
        {
            asn1sequence ncseq = dersequence.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.name_constraints));
            if (ncseq != null)
            {
                nc = nameconstraints.getinstance(ncseq);
            }
        }
        catch (exception e)
        {
            throw new extcertpathvalidatorexception("name constraints extension could not be decoded.", e, certpath,
                index);
        }
        if (nc != null)
        {

            //
            // (g) (1) permitted subtrees
            //
            generalsubtree[] permitted = nc.getpermittedsubtrees();
            if (permitted != null)
            {
                try
                {
                    nameconstraintvalidator.intersectpermittedsubtree(permitted);
                }
                catch (exception ex)
                {
                    throw new extcertpathvalidatorexception(
                        "permitted subtrees cannot be build from name constraints extension.", ex, certpath, index);
                }
            }

            //
            // (g) (2) excluded subtrees
            //
            generalsubtree[] excluded = nc.getexcludedsubtrees();
            if (excluded != null)
            {
                for (int i = 0; i != excluded.length; i++)
                try
                {
                        nameconstraintvalidator.addexcludedsubtree(excluded[i]);
                }
                catch (exception ex)
                {
                    throw new extcertpathvalidatorexception(
                        "excluded subtrees cannot be build from name constraints extension.", ex, certpath, index);
                }
            }
        }
    }

    /**
     * checks a distribution point for revocation information for the
     * certificate <code>cert</code>.
     *
     * @param dp                 the distribution point to consider.
     * @param paramspkix         pkix parameters.
     * @param cert               certificate to check if it is revoked.
     * @param validdate          the date when the certificate revocation status should be
     *                           checked.
     * @param defaultcrlsigncert the issuer certificate of the certificate <code>cert</code>.
     * @param defaultcrlsignkey  the public key of the issuer certificate
     *                           <code>defaultcrlsigncert</code>.
     * @param certstatus         the current certificate revocation status.
     * @param reasonmask         the reasons mask which is already checked.
     * @param certpathcerts      the certificates of the certification path.
     * @throws annotatedexception if the certificate is revoked or the status cannot be checked
     *                            or some error occurs.
     */
    private static void checkcrl(
        distributionpoint dp,
        extendedpkixparameters paramspkix,
        x509certificate cert,
        date validdate,
        x509certificate defaultcrlsigncert,
        publickey defaultcrlsignkey,
        certstatus certstatus,
        reasonsmask reasonmask,
        list certpathcerts)
        throws annotatedexception
    {
        date currentdate = new date(system.currenttimemillis());
        if (validdate.gettime() > currentdate.gettime())
        {
            throw new annotatedexception("validation time is in future.");
        }

        // (a)
        /*
         * we always get timely valid crls, so there is no step (a) (1).
         * "locally cached" crls are assumed to be in getstore(), additional
         * crls must be enabled in the extendedpkixparameters and are in
         * getadditionalstore()
         */

        set crls = certpathvalidatorutilities.getcompletecrls(dp, cert, currentdate, paramspkix);
        boolean validcrlfound = false;
        annotatedexception lastexception = null;
        iterator crl_iter = crls.iterator();

        while (crl_iter.hasnext() && certstatus.getcertstatus() == certstatus.unrevoked && !reasonmask.isallreasons())
        {
            try
            {
                x509crl crl = (x509crl)crl_iter.next();

                // (d)
                reasonsmask interimreasonsmask = rfc3280certpathutilities.processcrld(crl, dp);

                // (e)
                /*
                 * the reasons mask is updated at the end, so only valid crls
                 * can update it. if this crl does not contain new reasons it
                 * must be ignored.
                 */
                if (!interimreasonsmask.hasnewreasons(reasonmask))
                {
                    continue;
                }

                // (f)
                set keys = rfc3280certpathutilities.processcrlf(crl, cert, defaultcrlsigncert, defaultcrlsignkey,
                    paramspkix, certpathcerts);
                // (g)
                publickey key = rfc3280certpathutilities.processcrlg(crl, keys);

                x509crl deltacrl = null;

                if (paramspkix.isusedeltasenabled())
                {
                    // get delta crls
                    set deltacrls = certpathvalidatorutilities.getdeltacrls(currentdate, paramspkix, crl);
                    // we only want one valid delta crl
                    // (h)
                    deltacrl = rfc3280certpathutilities.processcrlh(deltacrls, key);
                }

                /*
                 * crl must be be valid at the current time, not the validation
                 * time. if a certificate is revoked with reason keycompromise,
                 * cacompromise, it can be used for forgery, also for the past.
                 * this reason may not be contained in older crls.
                 */

                /*
                 * in the chain model signatures stay valid also after the
                 * certificate has been expired, so they do not have to be in
                 * the crl validity time
                 */

                if (paramspkix.getvaliditymodel() != extendedpkixparameters.chain_validity_model)
                {
                    /*
                     * if a certificate has expired, but was revoked, it is not
                     * more in the crl, so it would be regarded as valid if the
                     * first check is not done
                     */
                    if (cert.getnotafter().gettime() < crl.getthisupdate().gettime())
                    {
                        throw new annotatedexception("no valid crl for current time found.");
                    }
                }

                rfc3280certpathutilities.processcrlb1(dp, cert, crl);

                // (b) (2)
                rfc3280certpathutilities.processcrlb2(dp, cert, crl);

                // (c)
                rfc3280certpathutilities.processcrlc(deltacrl, crl, paramspkix);

                // (i)
                rfc3280certpathutilities.processcrli(validdate, deltacrl, cert, certstatus, paramspkix);

                // (j)
                rfc3280certpathutilities.processcrlj(validdate, crl, cert, certstatus);

                // (k)
                if (certstatus.getcertstatus() == crlreason.removefromcrl)
                {
                    certstatus.setcertstatus(certstatus.unrevoked);
                }

                // update reasons mask
                reasonmask.addreasons(interimreasonsmask);

                set criticalextensions = crl.getcriticalextensionoids();
                if (criticalextensions != null)
                {
                    criticalextensions = new hashset(criticalextensions);
                    criticalextensions.remove(x509extensions.issuingdistributionpoint.getid());
                    criticalextensions.remove(x509extensions.deltacrlindicator.getid());

                    if (!criticalextensions.isempty())
                    {
                        throw new annotatedexception("crl contains unsupported critical extensions.");
                    }
                }

                if (deltacrl != null)
                {
                    criticalextensions = deltacrl.getcriticalextensionoids();
                    if (criticalextensions != null)
                    {
                        criticalextensions = new hashset(criticalextensions);
                        criticalextensions.remove(x509extensions.issuingdistributionpoint.getid());
                        criticalextensions.remove(x509extensions.deltacrlindicator.getid());
                        if (!criticalextensions.isempty())
                        {
                            throw new annotatedexception("delta crl contains unsupported critical extension.");
                        }
                    }
                }

                validcrlfound = true;
            }
            catch (annotatedexception e)
            {
                lastexception = e;
            }
        }
        if (!validcrlfound)
        {
            throw lastexception;
        }
    }

    /**
     * checks a certificate if it is revoked.
     *
     * @param paramspkix       pkix parameters.
     * @param cert             certificate to check if it is revoked.
     * @param validdate        the date when the certificate revocation status should be
     *                         checked.
     * @param sign             the issuer certificate of the certificate <code>cert</code>.
     * @param workingpublickey the public key of the issuer certificate <code>sign</code>.
     * @param certpathcerts    the certificates of the certification path.
     * @throws annotatedexception if the certificate is revoked or the status cannot be checked
     *                            or some error occurs.
     */
    protected static void checkcrls(
        extendedpkixparameters paramspkix,
        x509certificate cert,
        date validdate,
        x509certificate sign,
        publickey workingpublickey,
        list certpathcerts)
        throws annotatedexception
    {
        annotatedexception lastexception = null;
        crldistpoint crldp = null;
        try
        {
            crldp = crldistpoint.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.crl_distribution_points));
        }
        catch (exception e)
        {
            throw new annotatedexception("crl distribution point extension could not be read.", e);
        }
        try
        {
            certpathvalidatorutilities.addadditionalstoresfromcrldistributionpoint(crldp, paramspkix);
        }
        catch (annotatedexception e)
        {
            throw new annotatedexception(
                "no additional crl locations could be decoded from crl distribution point extension.", e);
        }
        certstatus certstatus = new certstatus();
        reasonsmask reasonsmask = new reasonsmask();

        boolean validcrlfound = false;
        // for each distribution point
        if (crldp != null)
        {
            distributionpoint dps[] = null;
            try
            {
                dps = crldp.getdistributionpoints();
            }
            catch (exception e)
            {
                throw new annotatedexception("distribution points could not be read.", e);
            }
            if (dps != null)
            {
                for (int i = 0; i < dps.length && certstatus.getcertstatus() == certstatus.unrevoked && !reasonsmask.isallreasons(); i++)
                {
                    extendedpkixparameters paramspkixclone = (extendedpkixparameters)paramspkix.clone();
                    try
                    {
                        checkcrl(dps[i], paramspkixclone, cert, validdate, sign, workingpublickey, certstatus, reasonsmask, certpathcerts);
                        validcrlfound = true;
                    }
                    catch (annotatedexception e)
                    {
                        lastexception = e;
                    }
                }
            }
        }

        /*
         * if the revocation status has not been determined, repeat the process
         * above with any available crls not specified in a distribution point
         * but issued by the certificate issuer.
         */

        if (certstatus.getcertstatus() == certstatus.unrevoked && !reasonsmask.isallreasons())
        {
            try
            {
                /*
                 * assume a dp with both the reasons and the crlissuer fields
                 * omitted and a distribution point name of the certificate
                 * issuer.
                 */
                asn1primitive issuer = null;
                try
                {
                    issuer = new asn1inputstream(certpathvalidatorutilities.getencodedissuerprincipal(cert).getencoded())
                        .readobject();
                }
                catch (exception e)
                {
                    throw new annotatedexception("issuer from certificate for crl could not be reencoded.", e);
                }
                distributionpoint dp = new distributionpoint(new distributionpointname(0, new generalnames(
                    new generalname(generalname.directoryname, issuer))), null, null);
                extendedpkixparameters paramspkixclone = (extendedpkixparameters)paramspkix.clone();
                checkcrl(dp, paramspkixclone, cert, validdate, sign, workingpublickey, certstatus, reasonsmask,
                    certpathcerts);
                validcrlfound = true;
            }
            catch (annotatedexception e)
            {
                lastexception = e;
            }
        }

        if (!validcrlfound)
        {
            if (lastexception instanceof annotatedexception)
            {
                throw lastexception;
            }

            throw new annotatedexception("no valid crl found.", lastexception);
        }
        if (certstatus.getcertstatus() != certstatus.unrevoked)
        {
            string message = "certificate revocation after " + certstatus.getrevocationdate();
            message += ", reason: " + crlreasons[certstatus.getcertstatus()];
            throw new annotatedexception(message);
        }
        if (!reasonsmask.isallreasons() && certstatus.getcertstatus() == certstatus.unrevoked)
        {
            certstatus.setcertstatus(certstatus.undetermined);
        }
        if (certstatus.getcertstatus() == certstatus.undetermined)
        {
            throw new annotatedexception("certificate status could not be determined.");
        }
    }

    protected static int preparenextcertj(
        certpath certpath,
        int index,
        int inhibitanypolicy)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (j)
        //
        derinteger iap = null;
        try
        {
            iap = derinteger.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.inhibit_any_policy));
        }
        catch (exception e)
        {
            throw new extcertpathvalidatorexception("inhibit any-policy extension cannot be decoded.", e, certpath,
                index);
        }

        if (iap != null)
        {
            int _inhibitanypolicy = iap.getvalue().intvalue();

            if (_inhibitanypolicy < inhibitanypolicy)
            {
                return _inhibitanypolicy;
            }
        }
        return inhibitanypolicy;
    }

    protected static void preparenextcertk(
        certpath certpath,
        int index)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (k)
        //
        basicconstraints bc = null;
        try
        {
            bc = basicconstraints.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.basic_constraints));
        }
        catch (exception e)
        {
            throw new extcertpathvalidatorexception("basic constraints extension cannot be decoded.", e, certpath,
                index);
        }
        if (bc != null)
        {
            if (!(bc.isca()))
            {
                throw new certpathvalidatorexception("not a ca certificate");
            }
        }
        else
        {
            throw new certpathvalidatorexception("intermediate certificate lacks basicconstraints");
        }
    }

    protected static int preparenextcertl(
        certpath certpath,
        int index,
        int maxpathlength)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (l)
        //
        if (!certpathvalidatorutilities.isselfissued(cert))
        {
            if (maxpathlength <= 0)
            {
                throw new extcertpathvalidatorexception("max path length not greater than zero", null, certpath, index);
            }

            return maxpathlength - 1;
        }
        return maxpathlength;
    }

    protected static int preparenextcertm(
        certpath certpath,
        int index,
        int maxpathlength)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);

        //
        // (m)
        //
        basicconstraints bc = null;
        try
        {
            bc = basicconstraints.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.basic_constraints));
        }
        catch (exception e)
        {
            throw new extcertpathvalidatorexception("basic constraints extension cannot be decoded.", e, certpath,
                index);
        }
        if (bc != null)
        {
            biginteger _pathlengthconstraint = bc.getpathlenconstraint();

            if (_pathlengthconstraint != null)
            {
                int _plc = _pathlengthconstraint.intvalue();

                if (_plc < maxpathlength)
                {
                    return _plc;
                }
            }
        }
        return maxpathlength;
    }

    protected static void preparenextcertn(
        certpath certpath,
        int index)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);

        //
        // (n)
        //
        boolean[] _usage = cert.getkeyusage();

        if ((_usage != null) && !_usage[rfc3280certpathutilities.key_cert_sign])
        {
            throw new extcertpathvalidatorexception(
                "issuer certificate keyusage extension is critical and does not permit key signing.", null,
                certpath, index);
        }
    }

    protected static void preparenextcerto(
        certpath certpath,
        int index,
        set criticalextensions,
        list pathcheckers)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (o)
        //

        iterator tmpiter;
        tmpiter = pathcheckers.iterator();
        while (tmpiter.hasnext())
        {
            try
            {
                ((pkixcertpathchecker)tmpiter.next()).check(cert, criticalextensions);
            }
            catch (certpathvalidatorexception e)
            {
                throw new certpathvalidatorexception(e.getmessage(), e.getcause(), certpath, index);
            }
        }
        if (!criticalextensions.isempty())
        {
            throw new extcertpathvalidatorexception("certificate has unsupported critical extension: " + criticalextensions, null, certpath,
                index);
        }
    }

    protected static int preparenextcerth1(
        certpath certpath,
        int index,
        int explicitpolicy)
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (h)
        //
        if (!certpathvalidatorutilities.isselfissued(cert))
        {
            //
            // (1)
            //
            if (explicitpolicy != 0)
            {
                return explicitpolicy - 1;
            }
        }
        return explicitpolicy;
    }

    protected static int preparenextcerth2(
        certpath certpath,
        int index,
        int policymapping)
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (h)
        //
        if (!certpathvalidatorutilities.isselfissued(cert))
        {
            //
            // (2)
            //
            if (policymapping != 0)
            {
                return policymapping - 1;
            }
        }
        return policymapping;
    }

    protected static int preparenextcerth3(
        certpath certpath,
        int index,
        int inhibitanypolicy)
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (h)
        //
        if (!certpathvalidatorutilities.isselfissued(cert))
        {
            //
            // (3)
            //
            if (inhibitanypolicy != 0)
            {
                return inhibitanypolicy - 1;
            }
        }
        return inhibitanypolicy;
    }

    protected static final string[] crlreasons = new string[]
        {
            "unspecified",
            "keycompromise",
            "cacompromise",
            "affiliationchanged",
            "superseded",
            "cessationofoperation",
            "certificatehold",
            "unknown",
            "removefromcrl",
            "privilegewithdrawn",
            "aacompromise"};

    protected static int wrapupcerta(
        int explicitpolicy,
        x509certificate cert)
    {
        //
        // (a)
        //
        if (!certpathvalidatorutilities.isselfissued(cert) && (explicitpolicy != 0))
        {
            explicitpolicy--;
        }
        return explicitpolicy;
    }

    protected static int wrapupcertb(
        certpath certpath,
        int index,
        int explicitpolicy)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        //
        // (b)
        //
        int tmpint;
        asn1sequence pc = null;
        try
        {
            pc = dersequence.getinstance(certpathvalidatorutilities.getextensionvalue(cert,
                rfc3280certpathutilities.policy_constraints));
        }
        catch (annotatedexception e)
        {
            throw new extcertpathvalidatorexception("policy constraints could not be decoded.", e, certpath, index);
        }
        if (pc != null)
        {
            enumeration policyconstraints = pc.getobjects();

            while (policyconstraints.hasmoreelements())
            {
                asn1taggedobject constraint = (asn1taggedobject)policyconstraints.nextelement();
                switch (constraint.gettagno())
                {
                    case 0:
                        try
                        {
                            tmpint = derinteger.getinstance(constraint, false).getvalue().intvalue();
                        }
                        catch (exception e)
                        {
                            throw new extcertpathvalidatorexception(
                                "policy constraints requireexplicitpolicy field could not be decoded.", e, certpath,
                                index);
                        }
                        if (tmpint == 0)
                        {
                            return 0;
                        }
                        break;
                }
            }
        }
        return explicitpolicy;
    }

    protected static void wrapupcertf(
        certpath certpath,
        int index,
        list pathcheckers,
        set criticalextensions)
        throws certpathvalidatorexception
    {
        list certs = certpath.getcertificates();
        x509certificate cert = (x509certificate)certs.get(index);
        iterator tmpiter;
        tmpiter = pathcheckers.iterator();
        while (tmpiter.hasnext())
        {
            try
            {
                ((pkixcertpathchecker)tmpiter.next()).check(cert, criticalextensions);
            }
            catch (certpathvalidatorexception e)
            {
                throw new extcertpathvalidatorexception("additional certificate path checker failed.", e, certpath,
                    index);
            }
        }

        if (!criticalextensions.isempty())
        {
            throw new extcertpathvalidatorexception("certificate has unsupported critical extension: " + criticalextensions, null, certpath,
                index);
        }
    }

    protected static pkixpolicynode wrapupcertg(
        certpath certpath,
        extendedpkixparameters paramspkix,
        set userinitialpolicyset,
        int index,
        list[] policynodes,
        pkixpolicynode validpolicytree,
        set acceptablepolicies)
        throws certpathvalidatorexception
    {
        int n = certpath.getcertificates().size();
        //
        // (g)
        //
        pkixpolicynode intersection;

        //
        // (g) (i)
        //
        if (validpolicytree == null)
        {
            if (paramspkix.isexplicitpolicyrequired())
            {
                throw new extcertpathvalidatorexception("explicit policy requested but none available.", null,
                    certpath, index);
            }
            intersection = null;
        }
        else if (certpathvalidatorutilities.isanypolicy(userinitialpolicyset)) // (g)
        // (ii)
        {
            if (paramspkix.isexplicitpolicyrequired())
            {
                if (acceptablepolicies.isempty())
                {
                    throw new extcertpathvalidatorexception("explicit policy requested but none available.", null,
                        certpath, index);
                }
                else
                {
                    set _validpolicynodeset = new hashset();

                    for (int j = 0; j < policynodes.length; j++)
                    {
                        list _nodedepth = policynodes[j];

                        for (int k = 0; k < _nodedepth.size(); k++)
                        {
                            pkixpolicynode _node = (pkixpolicynode)_nodedepth.get(k);

                            if (rfc3280certpathutilities.any_policy.equals(_node.getvalidpolicy()))
                            {
                                iterator _iter = _node.getchildren();
                                while (_iter.hasnext())
                                {
                                    _validpolicynodeset.add(_iter.next());
                                }
                            }
                        }
                    }

                    iterator _vpnsiter = _validpolicynodeset.iterator();
                    while (_vpnsiter.hasnext())
                    {
                        pkixpolicynode _node = (pkixpolicynode)_vpnsiter.next();
                        string _validpolicy = _node.getvalidpolicy();

                        if (!acceptablepolicies.contains(_validpolicy))
                        {
                            // validpolicytree =
                            // removepolicynode(validpolicytree, policynodes,
                            // _node);
                        }
                    }
                    if (validpolicytree != null)
                    {
                        for (int j = (n - 1); j >= 0; j--)
                        {
                            list nodes = policynodes[j];

                            for (int k = 0; k < nodes.size(); k++)
                            {
                                pkixpolicynode node = (pkixpolicynode)nodes.get(k);
                                if (!node.haschildren())
                                {
                                    validpolicytree = certpathvalidatorutilities.removepolicynode(validpolicytree,
                                        policynodes, node);
                                }
                            }
                        }
                    }
                }
            }

            intersection = validpolicytree;
        }
        else
        {
            //
            // (g) (iii)
            //
            // this implementation is not exactly same as the one described in
            // rfc3280.
            // however, as far as the validation result is concerned, both
            // produce
            // adequate result. the only difference is whether anypolicy is
            // remain
            // in the policy tree or not.
            //
            // (g) (iii) 1
            //
            set _validpolicynodeset = new hashset();

            for (int j = 0; j < policynodes.length; j++)
            {
                list _nodedepth = policynodes[j];

                for (int k = 0; k < _nodedepth.size(); k++)
                {
                    pkixpolicynode _node = (pkixpolicynode)_nodedepth.get(k);

                    if (rfc3280certpathutilities.any_policy.equals(_node.getvalidpolicy()))
                    {
                        iterator _iter = _node.getchildren();
                        while (_iter.hasnext())
                        {
                            pkixpolicynode _c_node = (pkixpolicynode)_iter.next();
                            if (!rfc3280certpathutilities.any_policy.equals(_c_node.getvalidpolicy()))
                            {
                                _validpolicynodeset.add(_c_node);
                            }
                        }
                    }
                }
            }

            //
            // (g) (iii) 2
            //
            iterator _vpnsiter = _validpolicynodeset.iterator();
            while (_vpnsiter.hasnext())
            {
                pkixpolicynode _node = (pkixpolicynode)_vpnsiter.next();
                string _validpolicy = _node.getvalidpolicy();

                if (!userinitialpolicyset.contains(_validpolicy))
                {
                    validpolicytree = certpathvalidatorutilities.removepolicynode(validpolicytree, policynodes, _node);
                }
            }

            //
            // (g) (iii) 4
            //
            if (validpolicytree != null)
            {
                for (int j = (n - 1); j >= 0; j--)
                {
                    list nodes = policynodes[j];

                    for (int k = 0; k < nodes.size(); k++)
                    {
                        pkixpolicynode node = (pkixpolicynode)nodes.get(k);
                        if (!node.haschildren())
                        {
                            validpolicytree = certpathvalidatorutilities.removepolicynode(validpolicytree, policynodes,
                                node);
                        }
                    }
                }
            }

            intersection = validpolicytree;
        }
        return intersection;
    }

}
