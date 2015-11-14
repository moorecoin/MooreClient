package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.vector;

import org.ripple.bouncycastle.asn1.x509.keyusage;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.util.publickeyfactory;

/**
 * ecdh key exchange (see rfc 4492)
 */
public class tlsecdhkeyexchange
    extends abstracttlskeyexchange
{

    protected tlssigner tlssigner;
    protected int[] namedcurves;
    protected short[] clientecpointformats, serverecpointformats;

    protected asymmetrickeyparameter serverpublickey;
    protected ecpublickeyparameters ecagreeserverpublickey;
    protected tlsagreementcredentials agreementcredentials;
    protected ecprivatekeyparameters ecagreeclientprivatekey;

    protected ecprivatekeyparameters ecagreeserverprivatekey;
    protected ecpublickeyparameters ecagreeclientpublickey;

    public tlsecdhkeyexchange(int keyexchange, vector supportedsignaturealgorithms, int[] namedcurves,
                              short[] clientecpointformats, short[] serverecpointformats)
    {

        super(keyexchange, supportedsignaturealgorithms);

        switch (keyexchange)
        {
        case keyexchangealgorithm.ecdhe_rsa:
            this.tlssigner = new tlsrsasigner();
            break;
        case keyexchangealgorithm.ecdhe_ecdsa:
            this.tlssigner = new tlsecdsasigner();
            break;
        case keyexchangealgorithm.ecdh_rsa:
        case keyexchangealgorithm.ecdh_ecdsa:
            this.tlssigner = null;
            break;
        default:
            throw new illegalargumentexception("unsupported key exchange algorithm");
        }

        this.keyexchange = keyexchange;
        this.namedcurves = namedcurves;
        this.clientecpointformats = clientecpointformats;
        this.serverecpointformats = serverecpointformats;
    }

    public void init(tlscontext context)
    {
        super.init(context);

        if (this.tlssigner != null)
        {
            this.tlssigner.init(context);
        }
    }

    public void skipservercredentials()
        throws ioexception
    {
        throw new tlsfatalalert(alertdescription.unexpected_message);
    }

    public void processservercertificate(certificate servercertificate)
        throws ioexception
    {

        if (servercertificate.isempty())
        {
            throw new tlsfatalalert(alertdescription.bad_certificate);
        }

        org.ripple.bouncycastle.asn1.x509.certificate x509cert = servercertificate.getcertificateat(0);

        subjectpublickeyinfo keyinfo = x509cert.getsubjectpublickeyinfo();
        try
        {
            this.serverpublickey = publickeyfactory.createkey(keyinfo);
        }
        catch (runtimeexception e)
        {
            throw new tlsfatalalert(alertdescription.unsupported_certificate);
        }

        if (tlssigner == null)
        {
            try
            {
                this.ecagreeserverpublickey = tlseccutils
                    .validateecpublickey((ecpublickeyparameters)this.serverpublickey);
            }
            catch (classcastexception e)
            {
                throw new tlsfatalalert(alertdescription.certificate_unknown);
            }

            tlsutils.validatekeyusage(x509cert, keyusage.keyagreement);
        }
        else
        {
            if (!tlssigner.isvalidpublickey(this.serverpublickey))
            {
                throw new tlsfatalalert(alertdescription.certificate_unknown);
            }

            tlsutils.validatekeyusage(x509cert, keyusage.digitalsignature);
        }

        super.processservercertificate(servercertificate);
    }

    public boolean requiresserverkeyexchange()
    {
        switch (keyexchange)
        {
        case keyexchangealgorithm.ecdhe_ecdsa:
        case keyexchangealgorithm.ecdhe_rsa:
        case keyexchangealgorithm.ecdh_anon:
            return true;
        default:
            return false;
        }
    }

    public void validatecertificaterequest(certificaterequest certificaterequest)
        throws ioexception
    {
        /*
         * rfc 4492 3. [...] the ecdsa_fixed_ecdh and rsa_fixed_ecdh mechanisms are usable with
         * ecdh_ecdsa and ecdh_rsa. their use with ecdhe_ecdsa and ecdhe_rsa is prohibited because
         * the use of a long-term ecdh client key would jeopardize the forward secrecy property of
         * these algorithms.
         */
        short[] types = certificaterequest.getcertificatetypes();
        for (int i = 0; i < types.length; ++i)
        {
            switch (types[i])
            {
            case clientcertificatetype.rsa_sign:
            case clientcertificatetype.dss_sign:
            case clientcertificatetype.ecdsa_sign:
            case clientcertificatetype.rsa_fixed_ecdh:
            case clientcertificatetype.ecdsa_fixed_ecdh:
                break;
            default:
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }
    }

    public void processclientcredentials(tlscredentials clientcredentials)
        throws ioexception
    {
        if (clientcredentials instanceof tlsagreementcredentials)
        {
            // todo validate client cert has matching parameters (see 'tlseccutils.areonsamecurve')?

            this.agreementcredentials = (tlsagreementcredentials)clientcredentials;
        }
        else if (clientcredentials instanceof tlssignercredentials)
        {
            // ok
        }
        else
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    public void generateclientkeyexchange(outputstream output)
        throws ioexception
    {
        if (agreementcredentials != null)
        {
            return;
        }

        asymmetriccipherkeypair ecagreeclientkeypair = tlseccutils.generateeckeypair(context.getsecurerandom(),
            ecagreeserverpublickey.getparameters());
        this.ecagreeclientprivatekey = (ecprivatekeyparameters)ecagreeclientkeypair.getprivate();

        byte[] point = tlseccutils.serializeecpublickey(serverecpointformats,
            (ecpublickeyparameters)ecagreeclientkeypair.getpublic());

        tlsutils.writeopaque8(point, output);
    }

    public void processclientcertificate(certificate clientcertificate)
        throws ioexception
    {

        // todo extract the public key
        // todo if the certificate is 'fixed', take the public key as ecagreeclientpublickey
    }

    public void processclientkeyexchange(inputstream input)
        throws ioexception
    {

        if (ecagreeclientpublickey != null)
        {
            // for ecdsa_fixed_ecdh and rsa_fixed_ecdh, the key arrived in the client certificate
            return;
        }

        byte[] point = tlsutils.readopaque8(input);

        ecdomainparameters curve_params = this.ecagreeserverprivatekey.getparameters();

        this.ecagreeclientpublickey = tlseccutils.validateecpublickey(tlseccutils.deserializeecpublickey(
            serverecpointformats, curve_params, point));
    }

    public byte[] generatepremastersecret()
        throws ioexception
    {
        if (agreementcredentials != null)
        {
            return agreementcredentials.generateagreement(ecagreeserverpublickey);
        }

        if (ecagreeserverprivatekey != null)
        {
            return tlseccutils.calculateecdhbasicagreement(ecagreeclientpublickey, ecagreeserverprivatekey);
        }

        if (ecagreeclientprivatekey != null)
        {
            return tlseccutils.calculateecdhbasicagreement(ecagreeserverpublickey, ecagreeclientprivatekey);
        }

        throw new tlsfatalalert(alertdescription.internal_error);
    }
}
