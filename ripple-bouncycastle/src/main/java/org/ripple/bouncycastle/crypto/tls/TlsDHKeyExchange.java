package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.outputstream;
import java.math.biginteger;
import java.util.vector;

import org.ripple.bouncycastle.asn1.x509.keyusage;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;
import org.ripple.bouncycastle.crypto.util.publickeyfactory;

/**
 * tls 1.0/1.1 dh key exchange.
 */
public class tlsdhkeyexchange
    extends abstracttlskeyexchange
{

    protected static final biginteger one = biginteger.valueof(1);
    protected static final biginteger two = biginteger.valueof(2);

    protected tlssigner tlssigner;
    protected dhparameters dhparameters;

    protected asymmetrickeyparameter serverpublickey;
    protected dhpublickeyparameters dhagreeserverpublickey;
    protected tlsagreementcredentials agreementcredentials;
    protected dhprivatekeyparameters dhagreeclientprivatekey;

    protected dhpublickeyparameters dhagreeclientpublickey;

    public tlsdhkeyexchange(int keyexchange, vector supportedsignaturealgorithms, dhparameters dhparameters)
    {

        super(keyexchange, supportedsignaturealgorithms);

        switch (keyexchange)
        {
        case keyexchangealgorithm.dh_rsa:
        case keyexchangealgorithm.dh_dss:
            this.tlssigner = null;
            break;
        case keyexchangealgorithm.dhe_rsa:
            this.tlssigner = new tlsrsasigner();
            break;
        case keyexchangealgorithm.dhe_dss:
            this.tlssigner = new tlsdsssigner();
            break;
        default:
            throw new illegalargumentexception("unsupported key exchange algorithm");
        }

        this.dhparameters = dhparameters;
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
                this.dhagreeserverpublickey = validatedhpublickey((dhpublickeyparameters)this.serverpublickey);
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
        case keyexchangealgorithm.dhe_dss:
        case keyexchangealgorithm.dhe_rsa:
        case keyexchangealgorithm.dh_anon:
            return true;
        default:
            return false;
        }
    }

    public void validatecertificaterequest(certificaterequest certificaterequest)
        throws ioexception
    {
        short[] types = certificaterequest.getcertificatetypes();
        for (int i = 0; i < types.length; ++i)
        {
            switch (types[i])
            {
            case clientcertificatetype.rsa_sign:
            case clientcertificatetype.dss_sign:
            case clientcertificatetype.rsa_fixed_dh:
            case clientcertificatetype.dss_fixed_dh:
            case clientcertificatetype.ecdsa_sign:
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
            // todo validate client cert has matching parameters (see 'arecompatibleparameters')?

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
        /*
         * rfc 2246 7.4.7.2 if the client certificate already contains a suitable diffie-hellman
         * key, then yc is implicit and does not need to be sent again. in this case, the client key
         * exchange message will be sent, but will be empty.
         */
        if (agreementcredentials == null)
        {
            this.dhagreeclientprivatekey = tlsdhutils.generateephemeralclientkeyexchange(context.getsecurerandom(),
                dhagreeserverpublickey.getparameters(), output);
        }
    }

    public byte[] generatepremastersecret()
        throws ioexception
    {
        if (agreementcredentials != null)
        {
            return agreementcredentials.generateagreement(dhagreeserverpublickey);
        }

        return calculatedhbasicagreement(dhagreeserverpublickey, dhagreeclientprivatekey);
    }

    protected boolean arecompatibleparameters(dhparameters a, dhparameters b)
    {
        return a.getp().equals(b.getp()) && a.getg().equals(b.getg());
    }

    protected byte[] calculatedhbasicagreement(dhpublickeyparameters publickey, dhprivatekeyparameters privatekey)
    {
        return tlsdhutils.calculatedhbasicagreement(publickey, privatekey);
    }

    protected asymmetriccipherkeypair generatedhkeypair(dhparameters dhparams)
    {
        return tlsdhutils.generatedhkeypair(context.getsecurerandom(), dhparams);
    }

    protected dhpublickeyparameters validatedhpublickey(dhpublickeyparameters key)
        throws ioexception
    {
        return tlsdhutils.validatedhpublickey(key);
    }
}
