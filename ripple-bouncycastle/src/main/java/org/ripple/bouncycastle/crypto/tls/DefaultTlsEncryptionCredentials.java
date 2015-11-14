package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.encodings.pkcs1encoding;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;

public class defaulttlsencryptioncredentials
    implements tlsencryptioncredentials
{
    protected tlscontext context;
    protected certificate certificate;
    protected asymmetrickeyparameter privatekey;

    public defaulttlsencryptioncredentials(tlscontext context, certificate certificate,
                                           asymmetrickeyparameter privatekey)
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
        }
        else
        {
            throw new illegalargumentexception("'privatekey' type not supported: "
                + privatekey.getclass().getname());
        }

        this.context = context;
        this.certificate = certificate;
        this.privatekey = privatekey;
    }

    public certificate getcertificate()
    {
        return certificate;
    }

    public byte[] decryptpremastersecret(byte[] encryptedpremastersecret)
        throws ioexception
    {

        pkcs1encoding encoding = new pkcs1encoding(new rsablindedengine());
        encoding.init(false, new parameterswithrandom(this.privatekey, context.getsecurerandom()));

        try
        {
            return encoding.processblock(encryptedpremastersecret, 0,
                encryptedpremastersecret.length);
        }
        catch (invalidciphertextexception e)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
    }
}
