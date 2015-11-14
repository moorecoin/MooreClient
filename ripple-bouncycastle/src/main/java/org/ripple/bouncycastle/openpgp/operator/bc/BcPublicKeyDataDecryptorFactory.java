package org.ripple.bouncycastle.openpgp.operator.bc;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedasymmetricblockcipher;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.elgamalprivatekeyparameters;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.operator.pgpdatadecryptor;
import org.ripple.bouncycastle.openpgp.operator.publickeydatadecryptorfactory;

/**
 * a decryptor factory for handling public key decryption operations.
 */
public class bcpublickeydatadecryptorfactory
    implements publickeydatadecryptorfactory
{
    private bcpgpkeyconverter keyconverter = new bcpgpkeyconverter();
    private pgpprivatekey privkey;

    public bcpublickeydatadecryptorfactory(pgpprivatekey privkey)
    {
        this.privkey = privkey;
    }

    public byte[] recoversessiondata(int keyalgorithm, biginteger[] seckeydata)
        throws pgpexception
    {
        try
        {
            asymmetricblockcipher c = bcimplprovider.createpublickeycipher(keyalgorithm);

            asymmetrickeyparameter key = keyconverter.getprivatekey(privkey);

            bufferedasymmetricblockcipher c1 = new bufferedasymmetricblockcipher(c);

            c1.init(false, key);

            if (keyalgorithm == pgppublickey.rsa_encrypt
                || keyalgorithm == pgppublickey.rsa_general)
            {
                byte[] bi = seckeydata[0].tobytearray();

                if (bi[0] == 0)
                {
                    c1.processbytes(bi, 1, bi.length - 1);
                }
                else
                {
                    c1.processbytes(bi, 0, bi.length);
                }
            }
            else
            {
                bcpgpkeyconverter converter = new bcpgpkeyconverter();
                elgamalprivatekeyparameters parms = (elgamalprivatekeyparameters) converter.getprivatekey(privkey);
                int size = (parms.getparameters().getp().bitlength() + 7) / 8;
                byte[] tmp = new byte[size];

                byte[] bi = seckeydata[0].tobytearray();
                if (bi.length > size)
                {
                    c1.processbytes(bi, 1, bi.length - 1);
                }
                else
                {
                    system.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                    c1.processbytes(tmp, 0, tmp.length);
                }

                bi = seckeydata[1].tobytearray();
                for (int i = 0; i != tmp.length; i++)
                {
                    tmp[i] = 0;
                }

                if (bi.length > size)
                {
                    c1.processbytes(bi, 1, bi.length - 1);
                }
                else
                {
                    system.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                    c1.processbytes(tmp, 0, tmp.length);
                }
            }

            return c1.dofinal();
        }
        catch (invalidciphertextexception e)
        {
            throw new pgpexception("exception encrypting session info: " + e.getmessage(), e);
        }

    }

    public pgpdatadecryptor createdatadecryptor(boolean withintegritypacket, int encalgorithm, byte[] key)
        throws pgpexception
    {
        blockcipher engine = bcimplprovider.createblockcipher(encalgorithm);

        return bcutil.createdatadecryptor(withintegritypacket, engine, key);
    }
}
