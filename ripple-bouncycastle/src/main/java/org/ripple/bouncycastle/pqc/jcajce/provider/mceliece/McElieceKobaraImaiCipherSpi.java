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
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecekobaraimaicipher;
import org.ripple.bouncycastle.pqc.jcajce.provider.util.asymmetrichybridcipher;

public class mceliecekobaraimaicipherspi
    extends asymmetrichybridcipher
    implements pkcsobjectidentifiers, x509objectidentifiers
{

    // todo digest needed?
    private digest digest;
    private mceliecekobaraimaicipher cipher;

    /**
     * buffer to store the input data
     */
    private bytearrayoutputstream buf = new bytearrayoutputstream();


    public mceliecekobaraimaicipherspi()
    {
        buf = new bytearrayoutputstream();
    }

    protected mceliecekobaraimaicipherspi(digest digest, mceliecekobaraimaicipher cipher)
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
     * @throws badpaddingexception if this cipher is in decryption mode, and (un)padding has
     * been requested, but the decrypted data is not bounded by
     * the appropriate padding bytes
     */
    public byte[] dofinal(byte[] input, int inoff, int inlen)
        throws badpaddingexception
    {
        update(input, inoff, inlen);
        if (opmode == encrypt_mode)
        {

            try
            {
                return cipher.messageencrypt(this.pad());
            }
            catch (exception e)
            {
                e.printstacktrace();
            }

        }
        else if (opmode == decrypt_mode)
        {
            byte[] inputofdecr = buf.tobytearray();
            buf.reset();

            try
            {
                return unpad(cipher.messagedecrypt(inputofdecr));
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

        buf.reset();
        cipherparameters param;
        param = mceliececca2keystoparams.generatepublickeyparameter((publickey)key);

        param = new parameterswithrandom(param, sr);
        digest.reset();
        cipher.init(true, param);
    }

    protected void initcipherdecrypt(key key, algorithmparameterspec params)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {

        buf.reset();
        cipherparameters param;
        param = mceliececca2keystoparams.generateprivatekeyparameter((privatekey)key);

        digest.reset();
        cipher.init(false, param);
    }

    public string getname()
    {
        return "mceliecekobaraimaicipher";
    }

    public int getkeysize(key key)
        throws invalidkeyexception
    {
        mceliececca2keyparameters mceliececca2keyparameters;
        if (key instanceof publickey)
        {
            mceliececca2keyparameters = (mceliececca2keyparameters)mceliececca2keystoparams.generatepublickeyparameter((publickey)key);
            return cipher.getkeysize(mceliececca2keyparameters);
        }
        else if (key instanceof privatekey)
        {
            mceliececca2keyparameters = (mceliececca2keyparameters)mceliececca2keystoparams.generateprivatekeyparameter((privatekey)key);
            return cipher.getkeysize(mceliececca2keyparameters);
        }
        else
        {
            throw new invalidkeyexception();
        }


    }

    /**
     * pad and return the message stored in the message buffer.
     *
     * @return the padded message
     */
    private byte[] pad()
    {
        buf.write(0x01);
        byte[] result = buf.tobytearray();
        buf.reset();
        return result;
    }

    /**
     * unpad a message.
     *
     * @param pmbytes the padded message
     * @return the message
     * @throws badpaddingexception if the padded message is invalid.
     */
    private byte[] unpad(byte[] pmbytes)
        throws badpaddingexception
    {
        // find first non-zero byte
        int index;
        for (index = pmbytes.length - 1; index >= 0 && pmbytes[index] == 0; index--)
        {
            ;
        }

        // check if padding byte is valid
        if (pmbytes[index] != 0x01)
        {
            throw new badpaddingexception("invalid ciphertext");
        }

        // extract and return message
        byte[] mbytes = new byte[index];
        system.arraycopy(pmbytes, 0, mbytes, 0, index);
        return mbytes;
    }


    public byte[] messageencrypt()
        throws illegalblocksizeexception, badpaddingexception, nosuchalgorithmexception
    {
        byte[] output = null;
        try
        {
            output = cipher.messageencrypt((this.pad()));
        }
        catch (exception e)
        {
            e.printstacktrace();
        }
        return output;
    }


    public byte[] messagedecrypt()
        throws illegalblocksizeexception, badpaddingexception, nosuchalgorithmexception
    {
        byte[] output = null;
        byte[] inputofdecr = buf.tobytearray();
        buf.reset();
        try
        {
            output = unpad(cipher.messagedecrypt(inputofdecr));
        }
        catch (exception e)
        {
            e.printstacktrace();
        }
        return output;
    }


    static public class mceliecekobaraimai
        extends mceliecekobaraimaicipherspi
    {
        public mceliecekobaraimai()
        {
            super(new sha1digest(), new mceliecekobaraimaicipher());
        }
    }

    static public class mceliecekobaraimai224
        extends mceliecekobaraimaicipherspi
    {
        public mceliecekobaraimai224()
        {
            super(new sha224digest(), new mceliecekobaraimaicipher());
        }
    }

    static public class mceliecekobaraimai256
        extends mceliecekobaraimaicipherspi
    {
        public mceliecekobaraimai256()
        {
            super(new sha256digest(), new mceliecekobaraimaicipher());
        }
    }

    static public class mceliecekobaraimai384
        extends mceliecekobaraimaicipherspi
    {
        public mceliecekobaraimai384()
        {
            super(new sha384digest(), new mceliecekobaraimaicipher());
        }
    }

    static public class mceliecekobaraimai512
        extends mceliecekobaraimaicipherspi
    {
        public mceliecekobaraimai512()
        {
            super(new sha512digest(), new mceliecekobaraimaicipher());
        }
    }


}
