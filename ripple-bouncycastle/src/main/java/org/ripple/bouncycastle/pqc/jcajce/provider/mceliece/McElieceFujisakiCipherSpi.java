package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.bytearrayoutputstream;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.nosuchalgorithmexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.illegalblocksizeexception;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2keyparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecefujisakicipher;
import org.ripple.bouncycastle.pqc.jcajce.provider.util.asymmetrichybridcipher;

public class mceliecefujisakicipherspi
    extends asymmetrichybridcipher
    implements pkcsobjectidentifiers, x509objectidentifiers
{
    // todo digest needed?
    private digest digest;
    private mceliecefujisakicipher cipher;

    /**
     * buffer to store the input data
     */
    private bytearrayoutputstream buf;


    protected mceliecefujisakicipherspi(digest digest, mceliecefujisakicipher cipher)
    {
        this.digest = digest;
        this.cipher = cipher;
        buf = new bytearrayoutputstream();

    }

    /**
     * continue a multiple-part encryption or decryption operation.
     *
     * @param input byte array containing the next part of the input
     * @param inoff index in the array where the input starts
     * @param inlen length of the input
     * @return the processed byte array.
     */
    public byte[] update(byte[] input, int inoff, int inlen)
    {
        buf.write(input, inoff, inlen);
        return new byte[0];
    }


    /**
     * encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. the data is encrypted or decrypted, depending on
     * how this cipher was initialized.
     *
     * @param input the input buffer
     * @param inoff the offset in input where the input starts
     * @param inlen the input length
     * @return the new buffer with the result
     * @throws badpaddingexception on deryption errors.
     */
    public byte[] dofinal(byte[] input, int inoff, int inlen)
        throws badpaddingexception
    {
        update(input, inoff, inlen);
        byte[] data = buf.tobytearray();
        buf.reset();
        if (opmode == encrypt_mode)
        {

            try
            {
                return cipher.messageencrypt(data);
            }
            catch (exception e)
            {
                e.printstacktrace();
            }

        }
        else if (opmode == decrypt_mode)
        {

            try
            {
                return cipher.messagedecrypt(data);
            }
            catch (exception e)
            {
                e.printstacktrace();
            }

        }
        return null;
    }


    protected int encryptoutputsize(int inlen)
    {
        return 0;
    }

    protected int decryptoutputsize(int inlen)
    {
        return 0;
    }

    protected void initcipherencrypt(key key, algorithmparameterspec params,
                                     securerandom sr)
        throws invalidkeyexception,
        invalidalgorithmparameterexception
    {

        cipherparameters param;
        param = mceliececca2keystoparams.generatepublickeyparameter((publickey)key);

        param = new parameterswithrandom(param, sr);
        digest.reset();
        cipher.init(true, param);

    }

    protected void initcipherdecrypt(key key, algorithmparameterspec params)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {

        cipherparameters param;
        param = mceliececca2keystoparams.generateprivatekeyparameter((privatekey)key);

        digest.reset();
        cipher.init(false, param);
    }

    public string getname()
    {
        return "mceliecefujisakicipher";
    }

    public int getkeysize(key key)
        throws invalidkeyexception
    {
        mceliececca2keyparameters mceliececca2keyparameters;
        if (key instanceof publickey)
        {
            mceliececca2keyparameters = (mceliececca2keyparameters)mceliececca2keystoparams.generatepublickeyparameter((publickey)key);
        }
        else
        {
            mceliececca2keyparameters = (mceliececca2keyparameters)mceliececca2keystoparams.generateprivatekeyparameter((privatekey)key);

        }


        return cipher.getkeysize(mceliececca2keyparameters);
    }

    public byte[] messageencrypt(byte[] input)
        throws illegalblocksizeexception, badpaddingexception, nosuchalgorithmexception
    {
        byte[] output = null;
        try
        {
            output = cipher.messageencrypt(input);
        }
        catch (exception e)
        {
            e.printstacktrace();
        }
        return output;
    }


    public byte[] messagedecrypt(byte[] input)
        throws illegalblocksizeexception, badpaddingexception, nosuchalgorithmexception
    {
        byte[] output = null;
        try
        {
            output = cipher.messagedecrypt(input);
        }
        catch (exception e)
        {
            e.printstacktrace();
        }
        return output;
    }


    //////////////////////////////////////////////////////////////////////////////////

    static public class mceliecefujisaki
        extends mceliecefujisakicipherspi
    {
        public mceliecefujisaki()
        {
            super(new sha1digest(), new mceliecefujisakicipher());
        }
    }

    static public class mceliecefujisaki224
        extends mceliecefujisakicipherspi
    {
        public mceliecefujisaki224()
        {
            super(new sha224digest(), new mceliecefujisakicipher());
        }
    }

    static public class mceliecefujisaki256
        extends mceliecefujisakicipherspi
    {
        public mceliecefujisaki256()
        {
            super(new sha256digest(), new mceliecefujisakicipher());
        }
    }

    static public class mceliecefujisaki384
        extends mceliecefujisakicipherspi
    {
        public mceliecefujisaki384()
        {
            super(new sha384digest(), new mceliecefujisakicipher());
        }
    }

    static public class mceliecefujisaki512
        extends mceliecefujisakicipherspi
    {
        public mceliecefujisaki512()
        {
            super(new sha512digest(), new mceliecefujisakicipher());
        }
    }


}
