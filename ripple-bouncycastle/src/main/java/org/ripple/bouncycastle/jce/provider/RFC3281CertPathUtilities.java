package org.ripple.bouncycastle.jce.provider;

import java.io.ioexception;
import java.security.invalidalgorithmparameterexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.principal;
import java.security.publickey;
import java.security.cert.certpath;
import java.security.cert.certpathbuilder;
import java.security.cert.certpathbuilderexception;
import java.security.cert.certpathbuilderresult;
import java.security.cert.certpathvalidator;
import java.security.cert.certpathvalidatorexception;
import java.security.cert.certpathvalidatorresult;
import java.security.cert.certificateexpiredexception;
import java.security.cert.certificatenotyetvalidexception;
import java.security.cert.trustanchor;
import java.security.cert.x509crl;
import java.security.cert.x509certificate;
import java.util.date;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.x509.crldistpoint;
import org.ripple.bouncycastle.asn1.x509.crlreason;
import org.ripple.bouncycastle.asn1.x509.distributionpoint;
import org.ripple.bouncycastle.asn1.x509.distributionpointname;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.targetinformation;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.jce.exception.extcertpathvalidatorexception;
import org.ripple.bouncycastle.x509.extendedpkixbuilderparameters;
import org.ripple.bouncycastle.x509.extendedpkixparameters;
import org.ripple.bouncycastle.x509.pkixattrcertchecker;
import org.ripple.bouncycastle.x509.x509attributecertificate;
import org.ripple.bouncycastle.x509.x509certstoreselector;

class rfc3281certpathutilities
{

    private static final string target_information = x509extensions.targetinformation
        .getid();

    private static final string no_rev_avail = x509extensions.norevavail
        .getid();

    private static final string crl_distribution_points = x509extensions.crldistributionpoints
        .getid();

    private static final string authority_info_access = x509extensions.authorityinfoaccess
        .getid();

    protected static void processattrcert7(x509attributecertificate attrcert,
        certpath certpath, certpath holdercertpath,
        extendedpkixparameters pkixparams) throws certpathvalidatorexception
    {
        // todo:
        // aa controls
        // attribute encryption
        // proxy
        set set = attrcert.getcriticalextensionoids();
        // 7.1
        // process extensions

        // target information checked in step 6 / x509attributecertstoreselector
        if (set.contains(target_information))
        {
            try
            {
                targetinformation.getinstance(certpathvalidatorutilities
                    .getextensionvalue(attrcert, target_information));
            }
            catch (annotatedexception e)
            {
                throw new extcertpathvalidatorexception(
                    "target information extension could not be read.", e);
            }
            catch (illegalargumentexception e)
            {
                throw new extcertpathvalidatorexception(
                    "target information extension could not be read.", e);
            }
        }
        set.remove(target_information);
        for (iterator it = pkixparams.getattrcertcheckers().iterator(); it
            .hasnext();)
        {
            ((pkixattrcertchecker) it.next()).check(attrcert, certpath,
                holdercertpath, set);
        }
        if (!set.isempty())
        {
            throw new certpathvalidatorexception(
                "attribute certificate contains unsupported critical extensions: "
                    + set);
        }
    }

    /**
     * checks if an attribute certificate is revoked.
     * 
     * @param attrcert attribute certificate to check if it is revoked.
     * @param paramspkix pkix parameters.
     * @param issuercert the issuer certificate of the attribute certificate
     *            <code>attrcert</code>.
     * @param validdate the date when the certificate revocation status should
     *            be checked.
     * @param certpathcerts the certificates of the certification path to be
     *            checked.
     * 
     * @throws certpathvalidatorexception if the certificate is revoked or the
     *             status cannot be checked or some error occurs.
     */
    protected static void checkcrls(x509attributecertificate attrcert,
        extendedpkixparameters paramspkix, x509certificate issuercert,
        date validdate, list certpathcerts) throws certpathvalidatorexception
    {
        if (paramspkix.isrevocationenabled())
        {
            // check if revocation is available
            if (attrcert.getextensionvalue(no_rev_avail) == null)
            {
                crldistpoint crldp = null;
                try
                {
                    crldp = crldistpoint.getinstance(certpathvalidatorutilities
                        .getextensionvalue(attrcert, crl_distribution_points));
                }
                catch (annotatedexception e)
                {
                    throw new certpathvalidatorexception(
                        "crl distribution point extension could not be read.",
                        e);
                }
                try
                {
                    certpathvalidatorutilities
                        .addadditionalstoresfromcrldistributionpoint(crldp,
                            paramspkix);
                }
                catch (annotatedexception e)
                {
                    throw new certpathvalidatorexception(
                        "no additional crl locations could be decoded from crl distribution point extension.",
                        e);
                }
                certstatus certstatus = new certstatus();
                reasonsmask reasonsmask = new reasonsmask();

                annotatedexception lastexception = null;
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
                        throw new extcertpathvalidatorexception(
                            "distribution points could not be read.", e);
                    }
                    try
                    {
                        for (int i = 0; i < dps.length
                            && certstatus.getcertstatus() == certstatus.unrevoked
                            && !reasonsmask.isallreasons(); i++)
                        {
                            extendedpkixparameters paramspkixclone = (extendedpkixparameters) paramspkix
                                .clone();
                            checkcrl(dps[i], attrcert, paramspkixclone,
                                validdate, issuercert, certstatus, reasonsmask,
                                certpathcerts);
                            validcrlfound = true;
                        }
                    }
                    catch (annotatedexception e)
                    {
                        lastexception = new annotatedexception(
                            "no valid crl for distribution point found.", e);
                    }
                }

                /*
                 * if the revocation status has not been determined, repeat the
                 * process above with any available crls not specified in a
                 * distribution point but issued by the certificate issuer.
                 */

                if (certstatus.getcertstatus() == certstatus.unrevoked
                    && !reasonsmask.isallreasons())
                {
                    try
                    {
                        /*
                         * assume a dp with both the reasons and the crlissuer
                         * fields omitted and a distribution point name of the
                         * certificate issuer.
                         */
                        asn1primitive issuer = null;
                        try
                        {

                            issuer = new asn1inputstream(
                                ((x500principal) attrcert.getissuer()
                                    .getprincipals()[0]).getencoded())
                                .readobject();
                        }
                        catch (exception e)
                        {
                            throw new annotatedexception(
                                "issuer from certificate for crl could not be reencoded.",
                                e);
                        }
                        distributionpoint dp = new distributionpoint(
                            new distributionpointname(0, new generalnames(
                                new generalname(generalname.directoryname,
                                    issuer))), null, null);
                        extendedpkixparameters paramspkixclone = (extendedpkixparameters) paramspkix
                            .clone();
                        checkcrl(dp, attrcert, paramspkixclone, validdate,
                            issuercert, certstatus, reasonsmask, certpathcerts);
                        validcrlfound = true;
                    }
                    catch (annotatedexception e)
                    {
                        lastexception = new annotatedexception(
                            "no valid crl for distribution point found.", e);
                    }
                }

                if (!validcrlfound)
                {
                    throw new extcertpathvalidatorexception(
                        "no valid crl found.", lastexception);
                }
                if (certstatus.getcertstatus() != certstatus.unrevoked)
                {
                    string message = "attribute certificate revocation after "
                        + certstatus.getrevocationdate();
                    message += ", reason: "
                        + rfc3280certpathutilities.crlreasons[certstatus
                            .getcertstatus()];
                    throw new certpathvalidatorexception(message);
                }
                if (!reasonsmask.isallreasons()
                    && certstatus.getcertstatus() == certstatus.unrevoked)
                {
                    certstatus.setcertstatus(certstatus.undetermined);
                }
                if (certstatus.getcertstatus() == certstatus.undetermined)
                {
                    throw new certpathvalidatorexception(
                        "attribute certificate status could not be determined.");
                }

            }
            else
            {
                if (attrcert.getextensionvalue(crl_distribution_points) != null
                    || attrcert.getextensionvalue(authority_info_access) != null)
                {
                    throw new certpathvalidatorexception(
                        "no rev avail extension is set, but also an ac revocation pointer.");
                }
            }
        }
    }

    protected static void additionalchecks(x509attributecertificate attrcert,
        extendedpkixparameters pkixparams) throws certpathvalidatorexception
    {
        // 1
        for (iterator it = pkixparams.getprohibitedacattributes().iterator(); it
            .hasnext();)
        {
            string oid = (string) it.next();
            if (attrcert.getattributes(oid) != null)
            {
                throw new certpathvalidatorexception(
                    "attribute certificate contains prohibited attribute: "
                        + oid + ".");
            }
        }
        for (iterator it = pkixparams.getnecessaryacattributes().iterator(); it
            .hasnext();)
        {
            string oid = (string) it.next();
            if (attrcert.getattributes(oid) == null)
            {
                throw new certpathvalidatorexception(
                    "attribute certificate does not contain necessary attribute: "
                        + oid + ".");
            }
        }
    }

    protected static void processattrcert5(x509attributecertificate attrcert,
        extendedpkixparameters pkixparams) throws certpathvalidatorexception
    {
        try
        {
            attrcert.checkvalidity(certpathvalidatorutilities
                .getvaliddate(pkixparams));
        }
        catch (certificateexpiredexception e)
        {
            throw new extcertpathvalidatorexception(
                "attribute certificate is not valid.", e);
        }
        catch (certificatenotyetvalidexception e)
        {
            throw new extcertpathvalidatorexception(
                "attribute certificate is not valid.", e);
        }
    }

    protected static void processattrcert4(x509certificate acissuercert,
        extendedpkixparameters pkixparams) throws certpathvalidatorexception
    {
        set set = pkixparams.gettrustedacissuers();
        boolean trusted = false;
        for (iterator it = set.iterator(); it.hasnext();)
        {
            trustanchor anchor = (trustanchor) it.next();
            if (acissuercert.getsubjectx500principal().getname("rfc2253")
                .equals(anchor.getcaname())
                || acissuercert.equals(anchor.gettrustedcert()))
            {
                trusted = true;
            }
        }
        if (!trusted)
        {
            throw new certpathvalidatorexception(
                "attribute certificate issuer is not directly trusted.");
        }
    }

    protected static void processattrcert3(x509certificate acissuercert,
        extendedpkixparameters pkixparams) throws certpathvalidatorexception
    {
        if (acissuercert.getkeyusage() != null
            && (!acissuercert.getkeyusage()[0] && !acissuercert.getkeyusage()[1]))
        {
            throw new certpathvalidatorexception(
                "attribute certificate issuer public key cannot be used to validate digital signatures.");
        }
        if (acissuercert.getbasicconstraints() != -1)
        {
            throw new certpathvalidatorexception(
                "attribute certificate issuer is also a public key certificate issuer.");
        }
    }

    protected static certpathvalidatorresult processattrcert2(
        certpath certpath, extendedpkixparameters pkixparams)
        throws certpathvalidatorexception
    {
        certpathvalidator validator = null;
        try
        {
            validator = certpathvalidator.getinstance("pkix", bouncycastleprovider.provider_name);
        }
        catch (nosuchproviderexception e)
        {
            throw new extcertpathvalidatorexception(
                "support class could not be created.", e);
        }
        catch (nosuchalgorithmexception e)
        {
            throw new extcertpathvalidatorexception(
                "support class could not be created.", e);
        }
        try
        {
            return validator.validate(certpath, pkixparams);
        }
        catch (certpathvalidatorexception e)
        {
            throw new extcertpathvalidatorexception(
                "certification path for issuer certificate of attribute certificate could not be validated.",
                e);
        }
        catch (invalidalgorithmparameterexception e)
        {
            // must be a programming error
            throw new runtimeexception(e.getmessage());
        }
    }

    /**
     * searches for a holder public key certificate and verifies its
     * certification path.
     * 
     * @param attrcert the attribute certificate.
     * @param pkixparams the pkix parameters.
     * @return the certificate path of the holder certificate.
     * @throws annotatedexception if
     *             <ul>
     *             <li>no public key certificate can be found although holder
     *             information is given by an entity name or a base certificate
     *             id
     *             <li>support classes cannot be created
     *             <li>no certification path for the public key certificate can
     *             be built
     *             </ul>
     */
    protected static certpath processattrcert1(
        x509attributecertificate attrcert, extendedpkixparameters pkixparams)
        throws certpathvalidatorexception
    {
        certpathbuilderresult result = null;
        // find holder pkcs
        set holderpkcs = new hashset();
        if (attrcert.getholder().getissuer() != null)
        {
            x509certstoreselector selector = new x509certstoreselector();
            selector.setserialnumber(attrcert.getholder().getserialnumber());
            principal[] principals = attrcert.getholder().getissuer();
            for (int i = 0; i < principals.length; i++)
            {
                try
                {
                    if (principals[i] instanceof x500principal)
                    {
                        selector.setissuer(((x500principal)principals[i])
                            .getencoded());
                    }
                    holderpkcs.addall(certpathvalidatorutilities
                        .findcertificates(selector, pkixparams.getstores()));
                }
                catch (annotatedexception e)
                {
                    throw new extcertpathvalidatorexception(
                        "public key certificate for attribute certificate cannot be searched.",
                        e);
                }
                catch (ioexception e)
                {
                    throw new extcertpathvalidatorexception(
                        "unable to encode x500 principal.", e);
                }
            }
            if (holderpkcs.isempty())
            {
                throw new certpathvalidatorexception(
                    "public key certificate specified in base certificate id for attribute certificate cannot be found.");
            }
        }
        if (attrcert.getholder().getentitynames() != null)
        {
            x509certstoreselector selector = new x509certstoreselector();
            principal[] principals = attrcert.getholder().getentitynames();
            for (int i = 0; i < principals.length; i++)
            {
                try
                {
                    if (principals[i] instanceof x500principal)
                    {
                        selector.setissuer(((x500principal) principals[i])
                            .getencoded());
                    }
                    holderpkcs.addall(certpathvalidatorutilities
                        .findcertificates(selector, pkixparams.getstores()));
                }
                catch (annotatedexception e)
                {
                    throw new extcertpathvalidatorexception(
                        "public key certificate for attribute certificate cannot be searched.",
                        e);
                }
                catch (ioexception e)
                {
                    throw new extcertpathvalidatorexception(
                        "unable to encode x500 principal.", e);
                }
            }
            if (holderpkcs.isempty())
            {
                throw new certpathvalidatorexception(
                    "public key certificate specified in entity name for attribute certificate cannot be found.");
            }
        }
        // verify cert paths for pkcs
        extendedpkixbuilderparameters params = (extendedpkixbuilderparameters) extendedpkixbuilderparameters
            .getinstance(pkixparams);
        certpathvalidatorexception lastexception = null;
        for (iterator it = holderpkcs.iterator(); it.hasnext();)
        {
            x509certstoreselector selector = new x509certstoreselector();
            selector.setcertificate((x509certificate) it.next());
            params.settargetconstraints(selector);
            certpathbuilder builder = null;
            try
            {
                builder = certpathbuilder.getinstance("pkix", bouncycastleprovider.provider_name);
            }
            catch (nosuchproviderexception e)
            {
                throw new extcertpathvalidatorexception(
                    "support class could not be created.", e);
            }
            catch (nosuchalgorithmexception e)
            {
                throw new extcertpathvalidatorexception(
                    "support class could not be created.", e);
            }
            try
            {
                result = builder.build(extendedpkixbuilderparameters
                    .getinstance(params));
            }
            catch (certpathbuilderexception e)
            {
                lastexception = new extcertpathvalidatorexception(
                    "certification path for public key certificate of attribute certificate could not be build.",
                    e);
            }
            catch (invalidalgorithmparameterexception e)
            {
                // must be a programming error
                throw new runtimeexception(e.getmessage());
            }
        }
        if (lastexception != null)
        {
            throw lastexception;
        }
        return result.getcertpath();
    }

    /**
     * 
     * checks a distribution point for revocation information for the
     * certificate <code>attrcert</code>.
     * 
     * @param dp the distribution point to consider.
     * @param attrcert the attribute certificate which should be checked.
     * @param paramspkix pkix parameters.
     * @param validdate the date when the certificate revocation status should
     *            be checked.
     * @param issuercert certificate to check if it is revoked.
     * @param reasonmask the reasons mask which is already checked.
     * @param certpathcerts the certificates of the certification path to be
     *            checked.
     * @throws annotatedexception if the certificate is revoked or the status
     *             cannot be checked or some error occurs.
     */
    private static void checkcrl(distributionpoint dp,
        x509attributecertificate attrcert, extendedpkixparameters paramspkix,
        date validdate, x509certificate issuercert, certstatus certstatus,
        reasonsmask reasonmask, list certpathcerts) throws annotatedexception
    {

        /*
         * 4.3.6 no revocation available
         * 
         * the norevavail extension, defined in [x.509-2000], allows an ac
         * issuer to indicate that no revocation information will be made
         * available for this ac.
         */
        if (attrcert.getextensionvalue(x509extensions.norevavail.getid()) != null)
        {
            return;
        }
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

        set crls = certpathvalidatorutilities.getcompletecrls(dp, attrcert,
            currentdate, paramspkix);
        boolean validcrlfound = false;
        annotatedexception lastexception = null;
        iterator crl_iter = crls.iterator();

        while (crl_iter.hasnext()
            && certstatus.getcertstatus() == certstatus.unrevoked
            && !reasonmask.isallreasons())
        {
            try
            {
                x509crl crl = (x509crl) crl_iter.next();

                // (d)
                reasonsmask interimreasonsmask = rfc3280certpathutilities
                    .processcrld(crl, dp);

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
                set keys = rfc3280certpathutilities.processcrlf(crl, attrcert,
                    null, null, paramspkix, certpathcerts);
                // (g)
                publickey key = rfc3280certpathutilities.processcrlg(crl, keys);

                x509crl deltacrl = null;

                if (paramspkix.isusedeltasenabled())
                {
                    // get delta crls
                    set deltacrls = certpathvalidatorutilities.getdeltacrls(
                        currentdate, paramspkix, crl);
                    // we only want one valid delta crl
                    // (h)
                    deltacrl = rfc3280certpathutilities.processcrlh(deltacrls,
                        key);
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
                 * the crl vality time
                 */

                if (paramspkix.getvaliditymodel() != extendedpkixparameters.chain_validity_model)
                {
                    /*
                     * if a certificate has expired, but was revoked, it is not
                     * more in the crl, so it would be regarded as valid if the
                     * first check is not done
                     */
                    if (attrcert.getnotafter().gettime() < crl.getthisupdate()
                        .gettime())
                    {
                        throw new annotatedexception(
                            "no valid crl for current time found.");
                    }
                }

                rfc3280certpathutilities.processcrlb1(dp, attrcert, crl);

                // (b) (2)
                rfc3280certpathutilities.processcrlb2(dp, attrcert, crl);

                // (c)
                rfc3280certpathutilities.processcrlc(deltacrl, crl, paramspkix);

                // (i)
                rfc3280certpathutilities.processcrli(validdate, deltacrl,
                    attrcert, certstatus, paramspkix);

                // (j)
                rfc3280certpathutilities.processcrlj(validdate, crl, attrcert,
                    certstatus);

                // (k)
                if (certstatus.getcertstatus() == crlreason.removefromcrl)
                {
                    certstatus.setcertstatus(certstatus.unrevoked);
                }

                // update reasons mask
                reasonmask.addreasons(interimreasonsmask);
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
}
