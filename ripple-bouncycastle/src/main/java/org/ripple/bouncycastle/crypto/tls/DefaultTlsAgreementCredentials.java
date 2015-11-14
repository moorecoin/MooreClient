package org.ripple.bouncycastle.crypto.tls;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.basicagreement;
import org.ripple.bouncycastle.crypto.agreement.dhbasicagreement;
import org.ripple.bouncycastle.crypto.agreement.ecdhbasicagreement;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.util.bigintegers;

public class defaulttlsagreementcredentials
    implements tlsagreementcredentials
{

    protected certificate certificate;
    protected asymmetrickeyparameter privatekey;

    protected basicagreement basicagreement;
    protected boolean truncateagreement;

    public defaulttlsagreementcredentials(certificate certificate, asymmetrickeyparameter privatekey)
    {
        if (certificate == null)
        {
            throw new illegalargumentexception("'certificate' cannot be null");
        }
        if (certificate.isempty())
        {
            throw new illegalargumentexception("'certificate' cannot be empty");
        }
        if (privatekey == null)
        {
            throw new illegalargumentexception("'privatekey' cannot be null");
        }
        if (!privatekey.isprivate())
        {
            throw new illegalargumentexception("'privatekey' must be private");
        }

        if (privatekey instanceof dhprivatekeyparameters)
        {
            basicagreement = new dhbasicagreement();
            truncateagreement = true;
        }
        else if (privatekey instanceof ecprivatekeyparameters)
        {
            basicagreement = new ecdhbasicagreement();
            truncateagreement = false;
        }
        else
        {
            throw new illegalargumentexception("'privatekey' type not supported: "
                + privatekey.getclass().getname());
        }

        this.certificate = certificate;
        this.privatekey = privatekey;
    }

    public certificate getcertificate()
    {
        return certificate;
    }

    public byte[] generateagreement(asymmetrickeyparameter peerpublickey)
    {
        basicagreement.init(privatekey);
        biginteger agreementvalue = basicagreement.calculateagreement(peerpublickey);

        if (truncateagreement)
        {
            return bigintegers.asunsignedbytearray(agreementvalue);
        }

        return bigintegers.asunsignedbytearray(basicagreement.getfieldsize(), agreementvalue);
    }
}
