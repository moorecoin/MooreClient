package org.ripple.bouncycastle.openpgp.operator.bc;

import java.io.outputstream;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsigner;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.util.io.teeoutputstream;

public class bcpgpcontentsignerbuilder
    implements pgpcontentsignerbuilder
{
    private bcpgpdigestcalculatorprovider digestcalculatorprovider = new bcpgpdigestcalculatorprovider();
    private bcpgpkeyconverter           keyconverter = new bcpgpkeyconverter();
    private int                         hashalgorithm;
    private securerandom                random;
    private int keyalgorithm;

    public bcpgpcontentsignerbuilder(int keyalgorithm, int hashalgorithm)
    {
        this.keyalgorithm = keyalgorithm;
        this.hashalgorithm = hashalgorithm;
    }

    public bcpgpcontentsignerbuilder setsecurerandom(securerandom random)
    {
        this.random = random;

        return this;
    }

    public pgpcontentsigner build(final int signaturetype, final pgpprivatekey privatekey)
        throws pgpexception
    {
        final pgpdigestcalculator digestcalculator = digestcalculatorprovider.get(hashalgorithm);
        final signer signer = bcimplprovider.createsigner(keyalgorithm, hashalgorithm);

        if (random != null)
        {
            signer.init(true, new parameterswithrandom(keyconverter.getprivatekey(privatekey), random));
        }
        else
        {
            signer.init(true, keyconverter.getprivatekey(privatekey));
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
                return privatekey.getkeyid();
            }

            public outputstream getoutputstream()
            {
                return new teeoutputstream(new signeroutputstream(signer), digestcalculator.getoutputstream());
            }

            public byte[] getsignature()
            {
                try
                {
                    return signer.generatesignature();
                }
                catch (cryptoexception e)
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
