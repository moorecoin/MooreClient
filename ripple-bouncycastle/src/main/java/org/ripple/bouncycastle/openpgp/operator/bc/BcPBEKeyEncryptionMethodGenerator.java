package org.ripple.bouncycastle.openpgp.operator.bc;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pbekeyencryptionmethodgenerator;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

/**
 * a bc lightweight method generator for supporting pbe based encryption operations.
 */
public class bcpbekeyencryptionmethodgenerator
    extends pbekeyencryptionmethodgenerator
{
    /**
     *  create a pbe encryption method generator using the provided calculator for key calculation.
     *
     * @param passphrase  the passphrase to use as the primary source of key material.
     * @param s2kdigestcalculator  the digest calculator to use for key calculation.
     */
    public bcpbekeyencryptionmethodgenerator(char[] passphrase, pgpdigestcalculator s2kdigestcalculator)
    {
        super(passphrase, s2kdigestcalculator);
    }

    /**
     * create a pbe encryption method generator using the default sha-1 digest calculator for key calculation.
     *
     * @param passphrase  the passphrase to use as the primary source of key material.
     */
    public bcpbekeyencryptionmethodgenerator(char[] passphrase)
    {
        this(passphrase, new sha1pgpdigestcalculator());
    }

    /**
     *  create a pbe encryption method generator using the provided calculator and s2k count for key calculation.
     *
     * @param passphrase  the passphrase to use as the primary source of key material.
     * @param s2kdigestcalculator  the digest calculator to use for key calculation.
     * @param s2kcount the s2k count to use.
     */
    public bcpbekeyencryptionmethodgenerator(char[] passphrase, pgpdigestcalculator s2kdigestcalculator, int s2kcount)
    {
        super(passphrase, s2kdigestcalculator, s2kcount);
    }

    /**
     * create a pbe encryption method generator using the default sha-1 digest calculator and
     * a s2k count other than the default of 0x60  for key calculation.
     *
     * @param passphrase the passphrase to use as the primary source of key material.
     * @param s2kcount the s2k count to use.
     */
    public bcpbekeyencryptionmethodgenerator(char[] passphrase, int s2kcount)
    {
        super(passphrase, new sha1pgpdigestcalculator(), s2kcount);
    }

    /**
     * provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current generator.
     */
    public pbekeyencryptionmethodgenerator setsecurerandom(securerandom random)
    {
        super.setsecurerandom(random);

        return this;
    }

    protected byte[] encryptsessioninfo(int encalgorithm, byte[] key, byte[] sessioninfo)
        throws pgpexception
    {
        try
        {
            blockcipher engine = bcimplprovider.createblockcipher(encalgorithm);
            bufferedblockcipher cipher = bcutil.createsymmetrickeywrapper(true, engine, key, new byte[engine.getblocksize()]);

            byte[] out = new byte[sessioninfo.length];

            int len = cipher.processbytes(sessioninfo, 0, sessioninfo.length, out, 0);

            len += cipher.dofinal(out, len);

            return out;
        }
        catch (invalidciphertextexception e)
        {
            throw new pgpexception("encryption failed: " + e.getmessage(), e);
        }
    }
}
