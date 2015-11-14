package org.ripple.bouncycastle.openpgp.operator.bc;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pbedatadecryptorfactory;
import org.ripple.bouncycastle.openpgp.operator.pgpdatadecryptor;

/**
 * a decryptor factory for handling pbe decryption operations.
 */
public class bcpbedatadecryptorfactory
    extends pbedatadecryptorfactory
{
    /**
     * base constructor.
     *
     * @param pass  the passphrase to use as the primary source of key material.
     * @param calculatorprovider   a digest calculator provider to provide calculators to support the key generation calculation required.
     */
    public bcpbedatadecryptorfactory(char[] pass, bcpgpdigestcalculatorprovider calculatorprovider)
    {
        super(pass, calculatorprovider);
    }

    public byte[] recoversessiondata(int keyalgorithm, byte[] key, byte[] seckeydata)
        throws pgpexception
    {
        try
        {
            if (seckeydata != null && seckeydata.length > 0)
            {
                blockcipher engine = bcimplprovider.createblockcipher(keyalgorithm);
                bufferedblockcipher cipher = bcutil.createsymmetrickeywrapper(false, engine, key, new byte[engine.getblocksize()]);

                byte[] out = new byte[seckeydata.length];

                int len = cipher.processbytes(seckeydata, 0, seckeydata.length, out, 0);

                len += cipher.dofinal(out, len);

                return out;
            }
            else
            {
                byte[] keybytes = new byte[key.length + 1];

                keybytes[0] = (byte)keyalgorithm;
                system.arraycopy(key, 0, keybytes, 1, key.length);

                return keybytes;
            }
        }
        catch (exception e)
        {
            throw new pgpexception("exception recovering session info", e);
        }
    }

    public pgpdatadecryptor createdatadecryptor(boolean withintegritypacket, int encalgorithm, byte[] key)
        throws pgpexception
    {
        blockcipher engine = bcimplprovider.createblockcipher(encalgorithm);

        return bcutil.createdatadecryptor(withintegritypacket, engine, key);
    }
}
