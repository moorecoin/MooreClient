package org.ripple.bouncycastle.pqc.jcajce.provider.util;

import java.io.bytearrayoutputstream;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.invalidparameterexception;
import java.security.key;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.shortbufferexception;


/**
 * the asymmetricblockcipher class extends cipherspiext.
 * note: some ciphers are using padding. oneandzeroespadding is used as default
 * padding. however padding can still be specified, but mode is not supported;
 * if you try to instantiate the cipher with something else than "none" as mode
 * nosuchalgorithmexception is thrown.
 */
public abstract class asymmetricblockcipher
    extends cipherspiext
{

    /**
     * parameterspec used with this cipher
     */
    protected algorithmparameterspec paramspec;

    /**
     * internal buffer
     */
    protected bytearrayoutputstream buf;

    /**
     * the maximum number of bytes the cipher can decrypt.
     */
    protected int maxplaintextsize;

    /**
     * the maximum number of bytes the cipher can encrypt.
     */
    protected int ciphertextsize;

    /**
     * the asymmetricblockcipher() constructor
     */
    public asymmetricblockcipher()
    {
        buf = new bytearrayoutputstream();
    }

    /**
     * return the block size (in bytes). note: although the ciphers extending
     * this class are not block ciphers, the method was adopted to return the
     * maximal plaintext and ciphertext sizes for non hybrid ciphers. if the
     * cipher is hybrid, it returns 0.
     *
     * @return if the cipher is not a hybrid one the max plain/cipher text size
     *         is returned, otherwise 0 is returned
     */
    public final int getblocksize()
    {
        return opmode == encrypt_mode ? maxplaintextsize : ciphertextsize;
    }

    /**
     * @return <tt>null</tt> since no initialization vector is used.
     */
    public final byte[] getiv()
    {
        return null;
    }

    /**
     * return the length in bytes that an output buffer would need to be in
     * order to hold the result of the next update or dofinal operation, given
     * the input length <tt>inlen</tt> (in bytes). this call takes into
     * account any unprocessed (buffered) data from a previous update call, and
     * padding. the actual output length of the next update() or dofinal() call
     * may be smaller than the length returned by this method.
     * <p/>
     * if the input length plus the length of the buffered data exceeds the
     * maximum length, <tt>0</tt> is returned.
     *
     * @param inlen the length of the input
     * @return the length of the ciphertext or <tt>0</tt> if the input is too
     *         long.
     */
    public final int getoutputsize(int inlen)
    {

        int totallen = inlen + buf.size();

        int maxlen = getblocksize();

        if (totallen > maxlen)
        {
            // the length of the input exceeds the maximal supported length
            return 0;
        }

        return maxlen;
    }

    /**
     * <p/>
     * returns the parameters used with this cipher.
     * <p/>
     * the returned parameters may be the same that were used to initialize this
     * cipher, or may contain the default set of parameters or a set of randomly
     * generated parameters used by the underlying cipher implementation
     * (provided that the underlying cipher implementation uses a default set of
     * parameters or creates new parameters if it needs parameters but was not
     * initialized with any).
     * <p/>
     *
     * @return the parameters used with this cipher, or null if this cipher does
     *         not use any parameters.
     */
    public final algorithmparameterspec getparameters()
    {
        return paramspec;
    }

    /**
     * initializes the cipher for encryption by forwarding it to
     * initencrypt(key, flexisecurerandom).
     * <p/>
     * <p/>
     * if this cipher requires any algorithm parameters that cannot be derived
     * from the given key, the underlying cipher implementation is supposed to
     * generate the required parameters itself (using provider-specific default
     * or random values) if it is being initialized for encryption, and raise an
     * invalidkeyexception if it is being initialized for decryption. the
     * generated parameters can be retrieved using enginegetparameters or
     * enginegetiv (if the parameter is an iv).
     *
     * @param key the encryption or decryption key.
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher.
     */
    public final void initencrypt(key key)
        throws invalidkeyexception
    {
        try
        {
            initencrypt(key, null, new securerandom());
        }
        catch (invalidalgorithmparameterexception e)
        {
            throw new invalidparameterexception(
                "this cipher needs algorithm parameters for initialization (cannot be null).");
        }
    }

    /**
     * initialize this cipher for encryption by forwarding it to
     * initencrypt(key, flexisecurerandom, algorithmparameterspec).
     * <p/>
     * if this cipher requires any algorithm parameters that cannot be derived
     * from the given key, the underlying cipher implementation is supposed to
     * generate the required parameters itself (using provider-specific default
     * or random values) if it is being initialized for encryption, and raise an
     * invalidkeyexception if it is being initialized for decryption. the
     * generated parameters can be retrieved using enginegetparameters or
     * enginegetiv (if the parameter is an iv).
     *
     * @param key    the encryption or decryption key.
     * @param random the source of randomness.
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher.
     */
    public final void initencrypt(key key, securerandom random)
        throws invalidkeyexception
    {

        try
        {
            initencrypt(key, null, random);
        }
        catch (invalidalgorithmparameterexception iape)
        {
            throw new invalidparameterexception(
                "this cipher needs algorithm parameters for initialization (cannot be null).");
        }
    }

    /**
     * initializes the cipher for encryption by forwarding it to
     * initencrypt(key, flexisecurerandom, algorithmparameterspec).
     *
     * @param key    the encryption or decryption key.
     * @param params the algorithm parameters.
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher.
     * @throws invalidalgorithmparameterexception if the given algortihm parameters are inappropriate for
     * this cipher, or if this cipher is being initialized for
     * decryption and requires algorithm parameters and params
     * is null.
     */
    public final void initencrypt(key key, algorithmparameterspec params)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        initencrypt(key, params, new securerandom());
    }

    /**
     * this method initializes the asymmetricblockcipher with a certain key for
     * data encryption.
     * <p/>
     * if this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from random.
     * <p/>
     * note that when a cipher object is initialized, it loses all
     * previously-acquired state. in other words, initializing a cipher is
     * equivalent to creating a new instance of that cipher and initializing it
     * <p/>
     *
     * @param key          the key which has to be used to encrypt data.
     * @param securerandom the source of randomness.
     * @param params       the algorithm parameters.
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher
     * @throws invalidalgorithmparameterexception if the given algorithm parameters are inappropriate for
     * this cipher, or if this cipher is being initialized for
     * decryption and requires algorithm parameters and params
     * is null.
     */
    public final void initencrypt(key key, algorithmparameterspec params,
                                  securerandom securerandom)
        throws invalidkeyexception,
        invalidalgorithmparameterexception
    {
        opmode = encrypt_mode;
        initcipherencrypt(key, params, securerandom);
    }

    /**
     * initialize the cipher for decryption by forwarding it to
     * {@link #initdecrypt(key, algorithmparameterspec)}.
     * <p/>
     * if this cipher requires any algorithm parameters that cannot be derived
     * from the given key, the underlying cipher implementation is supposed to
     * generate the required parameters itself (using provider-specific default
     * or random values) if it is being initialized for encryption, and raise an
     * invalidkeyexception if it is being initialized for decryption. the
     * generated parameters can be retrieved using enginegetparameters or
     * enginegetiv (if the parameter is an iv).
     *
     * @param key the encryption or decryption key.
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher.
     */
    public final void initdecrypt(key key)
        throws invalidkeyexception
    {
        try
        {
            initdecrypt(key, null);
        }
        catch (invalidalgorithmparameterexception iape)
        {
            throw new invalidparameterexception(
                "this cipher needs algorithm parameters for initialization (cannot be null).");
        }
    }

    /**
     * this method initializes the asymmetricblockcipher with a certain key for
     * data decryption.
     * <p/>
     * if this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from random.
     * <p/>
     * note that when a cipher object is initialized, it loses all
     * previously-acquired state. in other words, initializing a cipher is
     * equivalent to creating a new instance of that cipher and initializing it
     * <p/>
     *
     * @param key    the key which has to be used to decrypt data.
     * @param params the algorithm parameters.
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher
     * @throws invalidalgorithmparameterexception if the given algorithm parameters are inappropriate for
     * this cipher, or if this cipher is being initialized for
     * decryption and requires algorithm parameters and params
     * is null.
     */
    public final void initdecrypt(key key, algorithmparameterspec params)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        opmode = decrypt_mode;
        initcipherdecrypt(key, params);
    }

    /**
     * continue a multiple-part encryption or decryption operation. this method
     * just writes the input into an internal buffer.
     *
     * @param input byte array containing the next part of the input
     * @param inoff index in the array where the input starts
     * @param inlen length of the input
     * @return a new buffer with the result (always empty)
     */
    public final byte[] update(byte[] input, int inoff, int inlen)
    {
        if (inlen != 0)
        {
            buf.write(input, inoff, inlen);
        }
        return new byte[0];
    }

    /**
     * continue a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     *
     * @param input  the input buffer
     * @param inoff  the offset where the input starts
     * @param inlen  the input length
     * @param output the output buffer
     * @param outoff the offset where the result is stored
     * @return the length of the output (always 0)
     */
    public final int update(byte[] input, int inoff, int inlen, byte[] output,
                            int outoff)
    {
        update(input, inoff, inlen);
        return 0;
    }

    /**
     * finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     *
     * @param input the input buffer
     * @param inoff the offset where the input starts
     * @param inlen the input length
     * @return a new buffer with the result
     * @throws illegalblocksizeexception if the plaintext or ciphertext size is too large.
     * @throws badpaddingexception if the ciphertext is invalid.
     */
    public final byte[] dofinal(byte[] input, int inoff, int inlen)
        throws illegalblocksizeexception, badpaddingexception
    {

        checklength(inlen);
        update(input, inoff, inlen);
        byte[] mbytes = buf.tobytearray();
        buf.reset();

        switch (opmode)
        {
        case encrypt_mode:
            return messageencrypt(mbytes);

        case decrypt_mode:
            return messagedecrypt(mbytes);

        default:
            return null;

        }
    }

    /**
     * finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     *
     * @param input  the input buffer
     * @param inoff  the offset where the input starts
     * @param inlen  the input length
     * @param output the buffer for the result
     * @param outoff the offset where the result is stored
     * @return the output length
     * @throws shortbufferexception if the output buffer is too small to hold the result.
     * @throws illegalblocksizeexception if the plaintext or ciphertext size is too large.
     * @throws badpaddingexception if the ciphertext is invalid.
     */
    public final int dofinal(byte[] input, int inoff, int inlen, byte[] output,
                             int outoff)
        throws shortbufferexception, illegalblocksizeexception,
        badpaddingexception
    {

        if (output.length < getoutputsize(inlen))
        {
            throw new shortbufferexception("output buffer too short.");
        }

        byte[] out = dofinal(input, inoff, inlen);
        system.arraycopy(out, 0, output, outoff, out.length);
        return out.length;
    }

    /**
     * since asymmetric block ciphers do not support modes, this method does
     * nothing.
     *
     * @param modename the cipher mode (unused)
     */
    protected final void setmode(string modename)
    {
        // empty
    }

    /**
     * since asymmetric block ciphers do not support padding, this method does
     * nothing.
     *
     * @param paddingname the name of the padding scheme (not used)
     */
    protected final void setpadding(string paddingname)
    {
        // empty
    }

    /**
     * check if the message length plus the length of the input length can be
     * en/decrypted. this method uses the specific values
     * {@link #maxplaintextsize} and {@link #ciphertextsize} which are set by
     * the implementations. if the input length plus the length of the internal
     * buffer is greater than {@link #maxplaintextsize} for encryption or not
     * equal to {@link #ciphertextsize} for decryption, an
     * {@link illegalblocksizeexception} will be thrown.
     *
     * @param inlen length of the input to check
     * @throws illegalblocksizeexception if the input length is invalid.
     */
    protected void checklength(int inlen)
        throws illegalblocksizeexception
    {

        int inlength = inlen + buf.size();

        if (opmode == encrypt_mode)
        {
            if (inlength > maxplaintextsize)
            {
                throw new illegalblocksizeexception(
                    "the length of the plaintext (" + inlength
                        + " bytes) is not supported by "
                        + "the cipher (max. " + maxplaintextsize
                        + " bytes).");
            }
        }
        else if (opmode == decrypt_mode)
        {
            if (inlength != ciphertextsize)
            {
                throw new illegalblocksizeexception(
                    "illegal ciphertext length (expected " + ciphertextsize
                        + " bytes, was " + inlength + " bytes).");
            }
        }

    }

    /**
     * initialize the asymmetricblockcipher with a certain key for data
     * encryption.
     *
     * @param key    the key which has to be used to encrypt data
     * @param params the algorithm parameters
     * @param sr     the source of randomness
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher.
     * @throws invalidalgorithmparameterexception if the given parameters are inappropriate for
     * initializing this cipher.
     */
    protected abstract void initcipherencrypt(key key,
                                              algorithmparameterspec params, securerandom sr)
        throws invalidkeyexception, invalidalgorithmparameterexception;

    /**
     * initialize the asymmetricblockcipher with a certain key for data
     * encryption.
     *
     * @param key    the key which has to be used to decrypt data
     * @param params the algorithm parameters
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher
     * @throws invalidalgorithmparameterexception if the given parameters are inappropriate for
     * initializing this cipher.
     */
    protected abstract void initcipherdecrypt(key key,
                                              algorithmparameterspec params)
        throws invalidkeyexception,
        invalidalgorithmparameterexception;

    /**
     * encrypt the message stored in input. the method should also perform an
     * additional length check.
     *
     * @param input the message to be encrypted (usually the message length is
     *              less than or equal to maxplaintextsize)
     * @return the encrypted message (it has length equal to maxciphertextsize_)
     * @throws illegalblocksizeexception if the input is inappropriate for this cipher.
     * @throws badpaddingexception if the input format is invalid.
     */
    protected abstract byte[] messageencrypt(byte[] input)
        throws illegalblocksizeexception, badpaddingexception;

    /**
     * decrypt the ciphertext stored in input. the method should also perform an
     * additional length check.
     *
     * @param input the ciphertext to be decrypted (the ciphertext length is
     *              less than or equal to maxciphertextsize)
     * @return the decrypted message
     * @throws illegalblocksizeexception if the input is inappropriate for this cipher.
     * @throws badpaddingexception if the input format is invalid.
     */
    protected abstract byte[] messagedecrypt(byte[] input)
        throws illegalblocksizeexception, badpaddingexception;

}
