package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.security.provider;

import javax.crypto.cipher;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pbedatadecryptorfactory;
import org.ripple.bouncycastle.openpgp.operator.pgpdatadecryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculatorprovider;

public class jcepbedatadecryptorfactorybuilder
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());
    private pgpdigestcalculatorprovider calculatorprovider;

    /**
     * base constructor.
     *
     * @param calculatorprovider   a digest calculator provider to provide calculators to support the key generation calculation required.
     */
    public jcepbedatadecryptorfactorybuilder(pgpdigestcalculatorprovider calculatorprovider)
    {
        this.calculatorprovider = calculatorprovider;
    }

    /**
     * set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider  provider object for cryptographic primitives.
     * @return  the current builder.
     */
    public jcepbedatadecryptorfactorybuilder setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));

        return this;
    }

    /**
     * set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providername  the name of the provider to reference for cryptographic primitives.
     * @return  the current builder.
     */
    public jcepbedatadecryptorfactorybuilder setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));

        return this;
    }

    public pbedatadecryptorfactory build(char[] passphrase)
    {
         return new pbedatadecryptorfactory(passphrase, calculatorprovider)
         {
             public byte[] recoversessiondata(int keyalgorithm, byte[] key, byte[] seckeydata)
                 throws pgpexception
             {
                 try
                 {
                     if (seckeydata != null && seckeydata.length > 0)
                     {
                         string ciphername = pgputil.getsymmetricciphername(keyalgorithm);
                         cipher keycipher = helper.createcipher(ciphername + "/cfb/nopadding");

                         keycipher.init(cipher.decrypt_mode, new secretkeyspec(key, ciphername), new ivparameterspec(new byte[keycipher.getblocksize()]));

                         return keycipher.dofinal(seckeydata);
                     }
                     else
                     {
                         byte[] keybytes = new byte[key.length + 1];

                         keybytes[0] = (byte)keyalgorithm;
                         system.arraycopy(key, 0, keybytes, 1, key.length);

                         return keybytes;
                     }
                 }
                 catch (exception e)
                 {
                     throw new pgpexception("exception recovering session info", e);
                 }
             }

             public pgpdatadecryptor createdatadecryptor(boolean withintegritypacket, int encalgorithm, byte[] key)
                 throws pgpexception
             {
                 return helper.createdatadecryptor(withintegritypacket, encalgorithm, key);
             }
         };
    }
}
