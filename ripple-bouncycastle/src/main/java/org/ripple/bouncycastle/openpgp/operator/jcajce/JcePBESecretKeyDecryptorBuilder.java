package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.provider;

import javax.crypto.badpaddingexception;
import javax.crypto.cipher;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeydecryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculatorprovider;

public class jcepbesecretkeydecryptorbuilder
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());
    private pgpdigestcalculatorprovider calculatorprovider;

    private jcapgpdigestcalculatorproviderbuilder calculatorproviderbuilder;

    public jcepbesecretkeydecryptorbuilder()
    {
        this.calculatorproviderbuilder = new jcapgpdigestcalculatorproviderbuilder();
    }

    public jcepbesecretkeydecryptorbuilder(pgpdigestcalculatorprovider calculatorprovider)
    {
        this.calculatorprovider = calculatorprovider;
    }

    public jcepbesecretkeydecryptorbuilder setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));

        if (calculatorproviderbuilder != null)
        {
            calculatorproviderbuilder.setprovider(provider);
        }

        return this;
    }

    public jcepbesecretkeydecryptorbuilder setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));

        if (calculatorproviderbuilder != null)
        {
            calculatorproviderbuilder.setprovider(providername);
        }

        return this;
    }

    public pbesecretkeydecryptor build(char[] passphrase)
        throws pgpexception
    {
        if (calculatorprovider == null)
        {
            calculatorprovider = calculatorproviderbuilder.build();
        }

        return new pbesecretkeydecryptor(passphrase, calculatorprovider)
        {
            public byte[] recoverkeydata(int encalgorithm, byte[] key, byte[] iv, byte[] keydata, int keyoff, int keylen)
                throws pgpexception
            {
                try
                {
                    cipher c = helper.createcipher(pgputil.getsymmetricciphername(encalgorithm) + "/cfb/nopadding");

                    c.init(cipher.decrypt_mode, pgputil.makesymmetrickey(encalgorithm, key), new ivparameterspec(iv));

                    return c.dofinal(keydata, keyoff, keylen);
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
                    throw new pgpexception("invalid parameter: " + e.getmessage(), e);
                }
                catch (invalidkeyexception e)
                {
                    throw new pgpexception("invalid key: " + e.getmessage(), e);
                }
            }
        };
    }
}
