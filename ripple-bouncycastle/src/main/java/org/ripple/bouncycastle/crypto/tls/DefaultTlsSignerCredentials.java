package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;

public class defaulttlssignercredentials
    implements tlssignercredentials
{
    protected tlscontext context;
    protected certificate certificate;
    protected asymmetrickeyparameter privatekey;

    protected tlssigner signer;

    public defaulttlssignercredentials(tlscontext context, certificate certificate, asymmetrickeyparameter privatekey)
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

        if (privatekey instanceof rsakeyparameters)
        {
            this.signer = new tlsrsasigner();
        }
        else if (privatekey instanceof dsaprivatekeyparameters)
        {
            this.signer = new tlsdsssigner();
        }
        else if (privatekey instanceof ecprivatekeyparameters)
        {
            this.signer = new tlsecdsasigner();
        }
        else
        {
            throw new illegalargumentexception("'privatekey' type not supported: " + privatekey.getclass().getname());
        }

        this.signer.init(context);

        this.context = context;
        this.certificate = certificate;
        this.privatekey = privatekey;
    }

    public certificate getcertificate()
    {
        return certificate;
    }

    public byte[] generatecertificatesignature(byte[] md5andsha1)
        throws ioexception
    {
        try
        {
            return signer.generaterawsignature(privatekey, md5andsha1);
        }
        catch (cryptoexception e)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }
}
