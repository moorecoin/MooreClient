package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.io.outputstream;
import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.provider;
import java.security.securerandom;
import java.security.signature;
import java.security.signatureexception;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsigner;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.util.io.teeoutputstream;

public class jcapgpcontentsignerbuilder
    implements pgpcontentsignerbuilder
{
    private operatorhelper              helper = new operatorhelper(new defaultjcajcehelper());
    private jcapgpdigestcalculatorproviderbuilder digestcalculatorproviderbuilder = new jcapgpdigestcalculatorproviderbuilder();
    private jcapgpkeyconverter          keyconverter = new jcapgpkeyconverter();
    private int                         hashalgorithm;
    private securerandom                random;
    private int keyalgorithm;

    public jcapgpcontentsignerbuilder(int keyalgorithm, int hashalgorithm)
    {
        this.keyalgorithm = keyalgorithm;
        this.hashalgorithm = hashalgorithm;
    }

    public jcapgpcontentsignerbuilder setsecurerandom(securerandom random)
    {
        this.random = random;

        return this;
    }

    public jcapgpcontentsignerbuilder setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));
        keyconverter.setprovider(provider);
        digestcalculatorproviderbuilder.setprovider(provider);

        return this;
    }

    public jcapgpcontentsignerbuilder setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));
        keyconverter.setprovider(providername);
        digestcalculatorproviderbuilder.setprovider(providername);

        return this;
    }

    public jcapgpcontentsignerbuilder setdigestprovider(provider provider)
    {
        digestcalculatorproviderbuilder.setprovider(provider);

        return this;
    }

    public jcapgpcontentsignerbuilder setdigestprovider(string providername)
    {
        digestcalculatorproviderbuilder.setprovider(providername);

        return this;
    }

    public pgpcontentsigner build(final int signaturetype, pgpprivatekey privatekey)
        throws pgpexception
    {
        if (privatekey instanceof jcapgpprivatekey)
        {
            return build(signaturetype, privatekey.getkeyid(), ((jcapgpprivatekey)privatekey).getprivatekey());
        }
        else
        {
            return build(signaturetype, privatekey.getkeyid(), keyconverter.getprivatekey(privatekey));
        }
    }

    public pgpcontentsigner build(final int signaturetype, final long keyid, final privatekey privatekey)
        throws pgpexception
    {
        final pgpdigestcalculator digestcalculator = digestcalculatorproviderbuilder.build().get(hashalgorithm);
        final signature           signature = helper.createsignature(keyalgorithm, hashalgorithm);

        try
        {
            if (random != null)
            {
                signature.initsign(privatekey, random);
            }
            else
            {
                signature.initsign(privatekey);
            }
        }
        catch (invalidkeyexception e)
        {
           throw new pgpexception("invalid key.", e);
        }

        return new pgpcontentsigner()
        {
            public int gettype()
            {
                return signaturetype;
            }

            public int gethashalgorithm()
            {
                return hashalgorithm;
            }

            public int getkeyalgorithm()
            {
                return keyalgorithm;
            }

            public long getkeyid()
            {
                return keyid;
            }

            public outputstream getoutputstream()
            {
                return new teeoutputstream(new signatureoutputstream(signature), digestcalculator.getoutputstream());
            }

            public byte[] getsignature()
            {
                try
                {
                    return signature.sign();
                }
                catch (signatureexception e)
                {    // todo: need a specific runtime exception for pgp operators.
                    throw new illegalstateexception("unable to create signature");
                }
            }

            public byte[] getdigest()
            {
                return digestcalculator.getdigest();
            }
        };
    }
}
