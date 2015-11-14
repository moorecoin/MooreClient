package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.io.outputstream;
import java.security.invalidkeyexception;
import java.security.provider;
import java.security.signature;
import java.security.signatureexception;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifier;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifierbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifierbuilderprovider;

public class jcapgpcontentverifierbuilderprovider
    implements pgpcontentverifierbuilderprovider
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());
    private jcapgpkeyconverter keyconverter = new jcapgpkeyconverter();

    public jcapgpcontentverifierbuilderprovider()
    {
    }

    public jcapgpcontentverifierbuilderprovider setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));
        keyconverter.setprovider(provider);

        return this;
    }

    public jcapgpcontentverifierbuilderprovider setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));
        keyconverter.setprovider(providername);

        return this;
    }

    public pgpcontentverifierbuilder get(int keyalgorithm, int hashalgorithm)
        throws pgpexception
    {
        return new jcapgpcontentverifierbuilder(keyalgorithm, hashalgorithm);
    }

    private class jcapgpcontentverifierbuilder
        implements pgpcontentverifierbuilder
    {
        private int hashalgorithm;
        private int keyalgorithm;

        public jcapgpcontentverifierbuilder(int keyalgorithm, int hashalgorithm)
        {
            this.keyalgorithm = keyalgorithm;
            this.hashalgorithm = hashalgorithm;
        }

        public pgpcontentverifier build(final pgppublickey publickey)
            throws pgpexception
        {
            final signature signature = helper.createsignature(keyalgorithm, hashalgorithm);

            try
            {
                signature.initverify(keyconverter.getpublickey(publickey));
            }
            catch (invalidkeyexception e)
            {
                throw new pgpexception("invalid key.", e);
            }

            return new pgpcontentverifier()
            {
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
                    return publickey.getkeyid();
                }

                public boolean verify(byte[] expected)
                {
                    try
                    {
                        return signature.verify(expected);
                    }
                    catch (signatureexception e)
                    {   // todo: need a specific runtime exception for pgp operators.
                        throw new illegalstateexception("unable to verify signature");
                    }
                }

                public outputstream getoutputstream()
                {
                    return new signatureoutputstream(signature);
                }
            };
        }
    }
}
