package org.ripple.bouncycastle.pqc.crypto.mceliece;


import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.crypto.messageencryptor;

// todo should implement some interface?
public class mceliecefujisakidigestcipher
{

    private final digest messdigest;

    private final messageencryptor mceliececca2cipher;

    private boolean forencrypting;


    public mceliecefujisakidigestcipher(messageencryptor mceliececca2cipher, digest messdigest)
    {
        this.mceliececca2cipher = mceliececca2cipher;
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

        mceliececca2cipher.init(forencrypting, param);
    }


    public byte[] messageencrypt()
    {
        if (!forencrypting)
        {
            throw new illegalstateexception("mceliecefujisakidigestcipher not initialised for encrypting.");
        }

        byte[] hash = new byte[messdigest.getdigestsize()];
        messdigest.dofinal(hash, 0);
        byte[] enc = null;

        try
        {
            enc = mceliececca2cipher.messageencrypt(hash);
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
            throw new illegalstateexception("mceliecefujisakidigestcipher not initialised for decrypting.");
        }


        try
        {
            output = mceliececca2cipher.messagedecrypt(ciphertext);
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
