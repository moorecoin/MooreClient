package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.encodings.pkcs1encoding;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;

public class tlsrsautils
{
    public static byte[] generateencryptedpremastersecret(tlscontext context, rsakeyparameters rsaserverpublickey,
                                                          outputstream output)
        throws ioexception
    {
        /*
         * choose a premastersecret and send it encrypted to the server
         */
        byte[] premastersecret = new byte[48];
        context.getsecurerandom().nextbytes(premastersecret);
        tlsutils.writeversion(context.getclientversion(), premastersecret, 0);

        pkcs1encoding encoding = new pkcs1encoding(new rsablindedengine());
        encoding.init(true, new parameterswithrandom(rsaserverpublickey, context.getsecurerandom()));

        try
        {
            byte[] encryptedpremastersecret = encoding.processblock(premastersecret, 0, premastersecret.length);

            if (context.getserverversion().isssl())
            {
                // todo do any sslv3 servers actually expect the length?
                output.write(encryptedpremastersecret);
            }
            else
            {
                tlsutils.writeopaque16(encryptedpremastersecret, output);
            }
        }
        catch (invalidciphertextexception e)
        {
            /*
             * this should never happen, only during decryption.
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        return premastersecret;
    }
}
