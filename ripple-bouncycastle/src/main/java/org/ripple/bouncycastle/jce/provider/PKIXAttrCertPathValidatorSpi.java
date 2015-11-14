package org.ripple.bouncycastle.jce.provider;

import java.security.invalidalgorithmparameterexception;
import java.security.cert.certpath;
import java.security.cert.certpathparameters;
import java.security.cert.certpathvalidatorexception;
import java.security.cert.certpathvalidatorresult;
import java.security.cert.certpathvalidatorspi;
import java.security.cert.x509certificate;
import java.util.date;
import java.util.set;

import org.ripple.bouncycastle.jce.exception.extcertpathvalidatorexception;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.x509.extendedpkixparameters;
import org.ripple.bouncycastle.x509.x509attributecertstoreselector;
import org.ripple.bouncycastle.x509.x509attributecertificate;

/**
 * certpathvalidatorspi implementation for x.509 attribute certificates la rfc 3281.
 * 
 * @see org.ripple.bouncycastle.x509.extendedpkixparameters
 */
public class pkixattrcertpathvalidatorspi
    extends certpathvalidatorspi
{

    /**
     * validates an attribute certificate with the given certificate path.
     * 
     * <p>
     * <code>params</code> must be an instance of
     * <code>extendedpkixparameters</code>.
     * <p>
     * the target constraints in the <code>params</code> must be an
     * <code>x509attributecertstoreselector</code> with at least the attribute
     * certificate criterion set. obey that also target informations may be
     * necessary to correctly validate this attribute certificate.
     * <p>
     * the attribute certificate issuer must be added to the trusted attribute
     * issuers with {@link extendedpkixparameters#settrustedacissuers(set)}.
     * 
     * @param certpath the certificate path which belongs to the attribute
     *            certificate issuer public key certificate.
     * @param params the pkix parameters.
     * @return a <code>pkixcertpathvalidatorresult</code> of the result of
     *         validating the <code>certpath</code>.
     * @throws invalidalgorithmparameterexception if <code>params</code> is
     *             inappropriate for this validator.
     * @throws certpathvalidatorexception if the verification fails.
     */
    public certpathvalidatorresult enginevalidate(certpath certpath,
        certpathparameters params) throws certpathvalidatorexception,
        invalidalgorithmparameterexception
    {
        if (!(params instanceof extendedpkixparameters))
        {
            throw new invalidalgorithmparameterexception(
                "parameters must be a "
                    + extendedpkixparameters.class.getname() + " instance.");
        }
        extendedpkixparameters pkixparams = (extendedpkixparameters) params;

        selector certselect = pkixparams.gettargetconstraints();
        if (!(certselect instanceof x509attributecertstoreselector))
        {
            throw new invalidalgorithmparameterexception(
                "targetconstraints must be an instance of "
                    + x509attributecertstoreselector.class.getname() + " for "
                    + this.getclass().getname() + " class.");
        }
        x509attributecertificate attrcert = ((x509attributecertstoreselector) certselect)
            .getattributecert();

        certpath holdercertpath = rfc3281certpathutilities.processattrcert1(attrcert, pkixparams);
        certpathvalidatorresult result = rfc3281certpathutilities.processattrcert2(certpath, pkixparams);
        x509certificate issuercert = (x509certificate) certpath
            .getcertificates().get(0);
        rfc3281certpathutilities.processattrcert3(issuercert, pkixparams);
        rfc3281certpathutilities.processattrcert4(issuercert, pkixparams);
        rfc3281certpathutilities.processattrcert5(attrcert, pkixparams);
        // 6 already done in x509attributecertstoreselector
        rfc3281certpathutilities.processattrcert7(attrcert, certpath, holdercertpath, pkixparams);
        rfc3281certpathutilities.additionalchecks(attrcert, pkixparams);
        date date = null;
        try
        {
            date = certpathvalidatorutilities
                .getvalidcertdatefromvaliditymodel(pkixparams, null, -1);
        }
        catch (annotatedexception e)
        {
            throw new extcertpathvalidatorexception(
                "could not get validity date from attribute certificate.", e);
        }
        rfc3281certpathutilities.checkcrls(attrcert, pkixparams, issuercert, date, certpath.getcertificates());
        return result;
    }
}
