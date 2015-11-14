package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.provider;
import java.security.securerandom;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.secretkey;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pbekeyencryptionmethodgenerator;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

/**
 * jce based generator for password based encryption (pbe) data protection methods.
 */
public class jcepbekeyencryptionmethodgenerator
    extends pbekeyencryptionmethodgenerator
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());

    /**
     *  create a pbe encryption method generator using the provided calculator for key calculation.
     *
     * @param passphrase  the passphrase to use as the primary source of key material.
     * @param s2kdigestcalculator  the digest calculator to use for key calculation.
     */
    public jcepbekeyencryptionmethodgenerator(char[] passphrase, pgpdigestcalculator s2kdigestcalculator)
    {
        super(passphrase, s2kdigestcalculator);
    }

    /**
     * create a pbe encryption method generator using the default sha-1 digest calculator for key calculation.
     *
     * @param passphrase  the passphrase to use as the primary source of key material.
     */
    public jcepbekeyencryptionmethodgenerator(char[] passphrase)
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
    public jcepbekeyencryptionmethodgenerator(char[] passphrase, pgpdigestcalculator s2kdigestcalculator, int s2kcount)
    {
        super(passphrase, s2kdigestcalculator, s2kcount);
    }

    /**
     * create a pbe encryption method generator using the default sha-1 digest calculator and
     * a s2k count other than the default of 0x60  for key calculation
     *
     * @param passphrase the passphrase to use as the primary source of key material.
     * @param s2kcount the s2k count to use.
     */
    public jcepbekeyencryptionmethodgenerator(char[] passphrase, int s2kcount)
    {
        super(passphrase, new sha1pgpdigestcalculator(), s2kcount);
    }

    public jcepbekeyencryptionmethodgenerator setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));

        return this;
    }

    public jcepbekeyencryptionmethodgenerator setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));

        return this;
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
            string cname = pgputil.getsymmetricciphername(encalgorithm);
            cipher c = helper.createcipher(cname + "/cfb/nopadding");
            secretkey skey = new secretkeyspec(key, pgputil.getsymmetricciphername(encalgorithm));

            c.init(cipher.encrypt_mode, skey, new ivparameterspec(new byte[c.getblocksize()]));

            return c.dofinal(sessioninfo, 0, sessioninfo.length);
        }
        catch (illegalblocksizeexception e)
        {
            throw new pgpexception("illegal block size: " + e.getmessage(), e);
        }
        catch (badpaddingexception e)
        {
            throw new pgpexception("bad padding: " + e.getmessage(), e);
        }
        catch (invalidalgorithmparameterexception e)
        {
            throw new pgpexception("iv invalid: " + e.getmessage(), e);
        }
        catch (invalidkeyexception e)
        {
            throw new pgpexception("key invalid: " + e.getmessage(), e);
        }
    }
}
