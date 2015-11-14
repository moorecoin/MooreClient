package org.ripple.bouncycastle.openpgp.operator.bc;

import java.io.outputstream;

import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifier;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifierbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifierbuilderprovider;

public class bcpgpcontentverifierbuilderprovider
    implements pgpcontentverifierbuilderprovider
{
    private bcpgpkeyconverter keyconverter = new bcpgpkeyconverter();

    public bcpgpcontentverifierbuilderprovider()
    {
    }

    public pgpcontentverifierbuilder get(int keyalgorithm, int hashalgorithm)
        throws pgpexception
    {
        return new bcpgpcontentverifierbuilder(keyalgorithm, hashalgorithm);
    }

    private class bcpgpcontentverifierbuilder
        implements pgpcontentverifierbuilder
    {
        private int hashalgorithm;
        private int keyalgorithm;

        public bcpgpcontentverifierbuilder(int keyalgorithm, int hashalgorithm)
        {
            this.keyalgorithm = keyalgorithm;
            this.hashalgorithm = hashalgorithm;
        }

        public pgpcontentverifier build(final pgppublickey publickey)
            throws pgpexception
        {
            final signer signer = bcimplprovider.createsigner(keyalgorithm, hashalgorithm);

            signer.init(false, keyconverter.getpublickey(publickey));

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
                    return signer.verifysignature(expected);
                }

                public outputstream getoutputstream()
                {
                    return new signeroutputstream(signer);
                }
            };
        }
    }
}
