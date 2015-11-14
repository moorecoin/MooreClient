package org.ripple.bouncycastle.crypto.encodings;

import java.security.accesscontroller;
import java.security.privilegedaction;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;

/**
 * this does your basic pkcs 1 v1.5 padding - whether or not you should be using this
 * depends on your application - see pkcs1 version 2 for details.
 */
public class pkcs1encoding
    implements asymmetricblockcipher
{
    /**
     * some providers fail to include the leading zero in pkcs1 encoded blocks. if you need to
     * work with one of these set the system property org.bouncycastle.pkcs1.strict to false.
     * <p>
     * the system property is checked during construction of the encoding object, it is set to 
     * true by default.
     * </p>
     */
    public static final string strict_length_enabled_property = "org.bouncycastle.pkcs1.strict";
    
    private static final int header_length = 10;

    private securerandom            random;
    private asymmetricblockcipher   engine;
    private boolean                 forencryption;
    private boolean                 forprivatekey;
    private boolean                 usestrictlength;

    /**
     * basic constructor.
     * @param cipher
     */
    public pkcs1encoding(
        asymmetricblockcipher   cipher)
    {
        this.engine = cipher;
        this.usestrictlength = usestrict();
    }   

    //
    // for j2me compatibility
    //
    private boolean usestrict()
    {
        // required if security manager has been installed.
        string strict = (string)accesscontroller.doprivileged(new privilegedaction()
        {
            public object run()
            {
                return system.getproperty(strict_length_enabled_property);
            }
        });

        return strict == null || strict.equals("true");
    }

    public asymmetricblockcipher getunderlyingcipher()
    {
        return engine;
    }

    public void init(
        boolean             forencryption,
        cipherparameters    param)
    {
        asymmetrickeyparameter  kparam;

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom    rparam = (parameterswithrandom)param;

            this.random = rparam.getrandom();
            kparam = (asymmetrickeyparameter)rparam.getparameters();
        }
        else
        {
            this.random = new securerandom();
            kparam = (asymmetrickeyparameter)param;
        }

        engine.init(forencryption, param);

        this.forprivatekey = kparam.isprivate();
        this.forencryption = forencryption;
    }

    public int getinputblocksize()
    {
        int     baseblocksize = engine.getinputblocksize();

        if (forencryption)
        {
            return baseblocksize - header_length;
        }
        else
        {
            return baseblocksize;
        }
    }

    public int getoutputblocksize()
    {
        int     baseblocksize = engine.getoutputblocksize();

        if (forencryption)
        {
            return baseblocksize;
        }
        else
        {
            return baseblocksize - header_length;
        }
    }

    public byte[] processblock(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        if (forencryption)
        {
            return encodeblock(in, inoff, inlen);
        }
        else
        {
            return decodeblock(in, inoff, inlen);
        }
    }

    private byte[] encodeblock(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        if (inlen > getinputblocksize())
        {
            throw new illegalargumentexception("input data too large");
        }
        
        byte[]  block = new byte[engine.getinputblocksize()];

        if (forprivatekey)
        {
            block[0] = 0x01;                        // type code 1

            for (int i = 1; i != block.length - inlen - 1; i++)
            {
                block[i] = (byte)0xff;
            }
        }
        else
        {
            random.nextbytes(block);                // random fill

            block[0] = 0x02;                        // type code 2

            //
            // a zero byte marks the end of the padding, so all
            // the pad bytes must be non-zero.
            //
            for (int i = 1; i != block.length - inlen - 1; i++)
            {
                while (block[i] == 0)
                {
                    block[i] = (byte)random.nextint();
                }
            }
        }

        block[block.length - inlen - 1] = 0x00;       // mark the end of the padding
        system.arraycopy(in, inoff, block, block.length - inlen, inlen);

        return engine.processblock(block, 0, block.length);
    }

    /**
     * @exception invalidciphertextexception if the decrypted block is not in pkcs1 format.
     */
    private byte[] decodeblock(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        byte[]  block = engine.processblock(in, inoff, inlen);

        if (block.length < getoutputblocksize())
        {
            throw new invalidciphertextexception("block truncated");
        }

        byte type = block[0];

        if (forprivatekey)
        {
            if (type != 2)
            {
                throw new invalidciphertextexception("unknown block type");
            }
        }
        else
        {
            if (type != 1)
            {
                throw new invalidciphertextexception("unknown block type");
            }
        }

        if (usestrictlength && block.length != engine.getoutputblocksize())
        {
            throw new invalidciphertextexception("block incorrect size");
        }
        
        //
        // find and extract the message block.
        //
        int start;
        
        for (start = 1; start != block.length; start++)
        {
            byte pad = block[start];
            
            if (pad == 0)
            {
                break;
            }
            if (type == 1 && pad != (byte)0xff)
            {
                throw new invalidciphertextexception("block padding incorrect");
            }
        }

        start++;           // data should start at the next byte

        if (start > block.length || start < header_length)
        {
            throw new invalidciphertextexception("no data in block");
        }

        byte[]  result = new byte[block.length - start];

        system.arraycopy(block, start, result, 0, result.length);

        return result;
    }
}
