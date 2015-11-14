package org.ripple.bouncycastle.pqc.crypto.mceliece;


import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.crypto.messageencryptor;

// todo should implement some interface?
public class mceliecepkcsdigestcipher
{

    private final digest messdigest;

    private final messageencryptor mceliececipher;

    private boolean forencrypting;


    public mceliecepkcsdigestcipher(messageencryptor mceliececipher, digest messdigest)
    {
        this.mceliececipher = mceliececipher;
        this.messdigest = messdigest;
    }


    public void init(boolean forencrypting,
                     cipherparameters param)
    {

        this.forencrypting = forencrypting;
        asymmetrickeyparameter k;

        if (param instanceof parameterswithrandom)
        {
            k = (asymmetrickeyparameter)((parameterswithrandom)param).getparameters();
        }
        else
        {
            k = (asymmetrickeyparameter)param;
        }

        if (forencrypting && k.isprivate())
        {
            throw new illegalargumentexception("encrypting requires public key.");
        }

        if (!forencrypting && !k.isprivate())
        {
            throw new illegalargumentexception("decrypting requires private key.");
        }

        reset();

        mceliececipher.init(forencrypting, param);
    }


    public byte[] messageencrypt()
    {
        if (!forencrypting)
        {
            throw new illegalstateexception("mceliecepkcsdigestcipher not initialised for encrypting.");
        }

        byte[] hash = new byte[messdigest.getdigestsize()];
        messdigest.dofinal(hash, 0);
        byte[] enc = null;

        try
        {
            enc = mceliececipher.messageencrypt(hash);
        }
        catch (exception e)
        {
            e.printstacktrace();
        }


        return enc;
    }


    public byte[] messagedecrypt(byte[] ciphertext)
    {
        byte[] output = null;
        if (forencrypting)
        {
            throw new illegalstateexception("mceliecepkcsdigestcipher not initialised for decrypting.");
        }


        try
        {
            output = mceliececipher.messagedecrypt(ciphertext);
        }
        catch (exception e)
        {
            e.printstacktrace();
        }


        return output;
    }


    public void update(byte b)
    {
        messdigest.update(b);

    }

    public void update(byte[] in, int off, int len)
    {
        messdigest.update(in, off, len);

    }


    public void reset()
    {
        messdigest.reset();

    }


}
