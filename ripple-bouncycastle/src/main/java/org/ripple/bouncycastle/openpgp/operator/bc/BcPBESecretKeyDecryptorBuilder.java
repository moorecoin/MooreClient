package org.ripple.bouncycastle.openpgp.operator.bc;

import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeydecryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculatorprovider;

public class bcpbesecretkeydecryptorbuilder
{
    private pgpdigestcalculatorprovider calculatorprovider;

    public bcpbesecretkeydecryptorbuilder(pgpdigestcalculatorprovider calculatorprovider)
    {
        this.calculatorprovider = calculatorprovider;
    }

    public pbesecretkeydecryptor build(char[] passphrase)
    {
        return new pbesecretkeydecryptor(passphrase, calculatorprovider)
        {
            public byte[] recoverkeydata(int encalgorithm, byte[] key, byte[] iv, byte[] keydata, int keyoff, int keylen)
                throws pgpexception
            {
                try
                {
                    bufferedblockcipher c = bcutil.createsymmetrickeywrapper(false, bcimplprovider.createblockcipher(encalgorithm), key, iv);

                    byte[] out = new byte[keylen];
                    int    outlen = c.processbytes(keydata, keyoff, keylen, out, 0);

                    outlen += c.dofinal(out, outlen);

                    return out;
                }
                catch (invalidciphertextexception e)
                {
                    throw new pgpexception("decryption failed: " + e.getmessage(), e);
                }
            }
        };
    }
}
