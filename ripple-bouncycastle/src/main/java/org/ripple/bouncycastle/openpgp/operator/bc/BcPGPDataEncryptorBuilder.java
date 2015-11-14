package org.ripple.bouncycastle.openpgp.operator.bc;

import java.io.outputstream;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.io.cipheroutputstream;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pgpdataencryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdataencryptorbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

public class bcpgpdataencryptorbuilder
    implements pgpdataencryptorbuilder
{
    private securerandom   random;
    private boolean withintegritypacket;
    private int encalgorithm;

    public bcpgpdataencryptorbuilder(int encalgorithm)
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
    public bcpgpdataencryptorbuilder setwithintegritypacket(boolean withintegritypacket)
    {
        this.withintegritypacket = withintegritypacket;

        return this;
    }

    /**
     * provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current builder.
     */
    public bcpgpdataencryptorbuilder setsecurerandom(securerandom random)
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
        private final bufferedblockcipher c;

        mypgpdataencryptor(byte[] keybytes)
            throws pgpexception
        {
            blockcipher engine = bcimplprovider.createblockcipher(encalgorithm);

            try
            {
                c = bcutil.createstreamcipher(true, engine, withintegritypacket, keybytes);
            }
            catch (illegalargumentexception e)
            {
                throw new pgpexception("invalid parameters: " + e.getmessage(), e);
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
