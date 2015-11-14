package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.io.outputstream;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.provider;
import java.security.securerandom;

import javax.crypto.cipher;
import javax.crypto.cipheroutputstream;
import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pgpdataencryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdataencryptorbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

public class jcepgpdataencryptorbuilder
    implements pgpdataencryptorbuilder
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());
    private securerandom   random;
    private boolean withintegritypacket;
    private int encalgorithm;

    public jcepgpdataencryptorbuilder(int encalgorithm)
    {
        this.encalgorithm = encalgorithm;

        if (encalgorithm == 0)
        {
            throw new illegalargumentexception("null cipher specified");
        }
    }

    /**
     * determine whether or not the resulting encrypted data will be protected using an integrity packet.
     *
     * @param withintegritypacket true if an integrity packet is to be included, false otherwise.
     * @return  the current builder.
     */
    public jcepgpdataencryptorbuilder setwithintegritypacket(boolean withintegritypacket)
    {
        this.withintegritypacket = withintegritypacket;

        return this;
    }

    public jcepgpdataencryptorbuilder setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));

        return this;
    }

    public jcepgpdataencryptorbuilder setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));

        return this;
    }

    /**
     * provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current builder.
     */
    public jcepgpdataencryptorbuilder setsecurerandom(securerandom random)
    {
        this.random = random;

        return this;
    }

    public int getalgorithm()
    {
        return encalgorithm;
    }

    public securerandom getsecurerandom()
    {
        if (random == null)
        {
            random = new securerandom();
        }

        return random;
    }

    public pgpdataencryptor build(byte[] keybytes)
        throws pgpexception
    {
        return new mypgpdataencryptor(keybytes);
    }

    private class mypgpdataencryptor
        implements pgpdataencryptor
    {
        private final cipher c;

        mypgpdataencryptor(byte[] keybytes)
            throws pgpexception
        {
            c = helper.createstreamcipher(encalgorithm, withintegritypacket);

            byte[] iv = new byte[c.getblocksize()];

            try
            {
                c.init(cipher.encrypt_mode, pgputil.makesymmetrickey(encalgorithm, keybytes), new ivparameterspec(iv));
            }
            catch (invalidkeyexception e)
            {
                throw new pgpexception("invalid key: " + e.getmessage(), e);
            }
            catch (invalidalgorithmparameterexception e)
            {
                throw new pgpexception("imvalid algorithm parameter: " + e.getmessage(), e);
            }
        }

        public outputstream getoutputstream(outputstream out)
        {
            return new cipheroutputstream(out, c);
        }

        public pgpdigestcalculator getintegritycalculator()
        {
            if (withintegritypacket)
            {
                return new sha1pgpdigestcalculator();
            }

            return null;
        }

        public int getblocksize()
        {
            return c.getblocksize();
        }
    }
}
