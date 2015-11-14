package org.ripple.bouncycastle.pqc.jcajce.provider.util;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.invalidparameterexception;
import java.security.key;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.shortbufferexception;

/**
 * the asymmetrichybridcipher class extends cipherspiext.
 * note: some ciphers are using padding. oneandzeroespadding is used as default
 * padding. however padding can still be specified, but mode is not supported;
 * if you try to instantiate the cipher with something else than "none" as mode,
 * nosuchalgorithmexception is thrown.
 */
public abstract class asymmetrichybridcipher
    extends cipherspiext
{

    /**
     * parameterspec used with this cipher
     */
    protected algorithmparameterspec paramspec;

    /**
     * since asymmetric hybrid ciphers do not support modes, this method does
     * nothing.
     *
     * @param modename the cipher mode (unused)
     */
    protected final void setmode(string modename)
    {
        // empty
    }

    /**
     * since asymmetric hybrid ciphers do not support padding, this method does
     * nothing.
     *
     * @param paddingname the name of the padding scheme (not used)
     */
    protected final void setpadding(string paddingname)
    {
        // empty
    }

    /**
     * @return <tt>null</tt> since no initialization vector is used.
     */
    public final byte[] getiv()
    {
        return null;
    }

    /**
     * @return 0 since the implementing algorithms are not block ciphers
     */
    public final int getblocksize()
    {
        return 0;
    }

    /**
     * return the parameters used with this cipher.
     * <p/>
     * the returned parameters may be the same that were used to initialize this
     * cipher, or may contain the default set of parameters or a set of randomly
     * generated parameters used by the underlying cipher implementation
     * (provided that the underlying cipher implementation uses a default set of
     * parameters or creates new parameters if it needs parameters but was not
     * initialized with any).
     *
     * @return the parameters used with this cipher, or <tt>null</tt> if this
     *         cipher does not use any parameters.
     */
    public final algorithmparameterspec getparameters()
    {
        return paramspec;
    }

    /**
     * return the length in bytes that an output buffer would need to be in
     * order to hold the result of the next update or dofinal operation, given
     * the input length <tt>inlen</tt> (in bytes). this call takes into
     * account any unprocessed (buffered) data from a previous update call, and
     * padding. the actual output length of the next update() or dofinal() call
     * may be smaller than the length returned by this method.
     *
     * @param inlen the length of the input
     * @return the length of the output of the next <tt>update()</tt> or
     *         <tt>dofinal()</tt> call
     */
    public final int getoutputsize(int inlen)
    {
        return opmode == encrypt_mode ? encryptoutputsize(inlen)
            : decryptoutputsize(inlen);
    }

    /**
     * initialize the cipher for encryption by forwarding it to
     * {@link #initencrypt(key, algorithmparameterspec, securerandom)}.
     * <p/>
     * if this cipher requires any algorithm parameters that cannot be derived
     * from the given key, the underlying cipher implementation is supposed to
     * generate the required parameters itself (using provider-specific default
     * or random values) if it is being initialized for encryption, and raise an
     * invalidkeyexception if it is being initialized for decryption. the
     * generated parameters can be retrieved using {@link #getparameters()}.
     *
     * @param key the encryption key
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher.
     * @throws invalidparameterexception if this cipher needs algorithm parameters for
     * initialization and cannot generate parameters itself.
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
     * {@link #initencrypt(key, algorithmparameterspec, securerandom)}.
     * <p/>
     * if this cipher requires any algorithm parameters that cannot be derived
     * from the given key, the underlying cipher implementation is supposed to
     * generate the required parameters itself (using provider-specific default
     * or random values) if it is being initialized for encryption, and raise an
     * invalidkeyexception if it is being initialized for decryption. the
     * generated parameters can be retrieved using {@link #getparameters()}.
     *
     * @param key    the encryption key
     * @param random the source of randomness
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher.
     * @throws invalidparameterexception if this cipher needs algorithm parameters for
     * initialization and cannot generate parameters itself.
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
     * initialize the cipher for encryption by forwarding it to initencrypt(key,
     * flexisecurerandom, algorithmparameterspec).
     *
     * @param key    the encryption key
     * @param params the algorithm parameters
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher.
     * @throws invalidalgorithmparameterexception if the given algorithm parameters are inappropriate for
     * this cipher, or if this cipher is initialized with
     * <tt>null</tt> parameters and cannot generate parameters
     * itself.
     */
    public final void initencrypt(key key, algorithmparameterspec params)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        initencrypt(key, params, new securerandom());
    }

    /**
     * initialize the cipher with a certain key for data encryption.
     * <p/>
     * if this cipher requires any random bytes (e.g., for parameter
     * generation), it will get them from <tt>random</tt>.
     * <p/>
     * note that when a cipher object is initialized, it loses all
     * previously-acquired state. in other words, initializing a cipher is
     * equivalent to creating a new instance of that cipher and initializing it.
     *
     * @param key    the encryption key
     * @param random the source of randomness
     * @param params the algorithm parameters
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher
     * @throws invalidalgorithmparameterexception if the given algorithm parameters are inappropriate for
     * this cipher, or if this cipher is initialized with
     * <tt>null</tt> parameters and cannot generate parameters
     * itself.
     */
    public final void initencrypt(key key, algorithmparameterspec params,
                                  securerandom random)
        throws invalidkeyexception,
        invalidalgorithmparameterexception
    {
        opmode = encrypt_mode;
        initcipherencrypt(key, params, random);
    }

    /**
     * initialize the cipher for decryption by forwarding it to initdecrypt(key,
     * flexisecurerandom).
     * <p/>
     * if this cipher requires any algorithm parameters that cannot be derived
     * from the given key, the underlying cipher implementation is supposed to
     * generate the required parameters itself (using provider-specific default
     * or random values) if it is being initialized for encryption, and raise an
     * invalidkeyexception if it is being initialized for decryption. the
     * generated parameters can be retrieved using {@link #getparameters()}.
     *
     * @param key the decryption key
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
     * initialize the cipher with a certain key for data decryption.
     * <p/>
     * if this cipher requires any random bytes (e.g., for parameter
     * generation), it will get them from <tt>random</tt>.
     * <p/>
     * note that when a cipher object is initialized, it loses all
     * previously-acquired state. in other words, initializing a cipher is
     * equivalent to creating a new instance of that cipher and initializing it
     *
     * @param key    the decryption key
     * @param params the algorithm parameters
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * cipher
     * @throws invalidalgorithmparameterexception if the given algorithm parameters are inappropriate for
     * this cipher, or if this cipher is initialized with
     * <tt>null</tt> parameters and cannot generate parameters
     * itself.
     */
    public final void initdecrypt(key key, algorithmparameterspec params)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        opmode = decrypt_mode;
        initcipherdecrypt(key, params);
    }

    /**
     * continue a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     *
     * @param input the input buffer
     * @param inoff the offset where the input starts
     * @param inlen the input length
     * @return a new buffer with the result (maybe an empty byte array)
     */
    public abstract byte[] update(byte[] input, int inoff, int inlen);

    /**
     * continue a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     *
     * @param input  the input buffer
     * @param inoff  the offset where the input starts
     * @param inlen  the input length
     * @param output the output buffer
     * @param outoff the offset where the result is stored
     * @return the length of the output
     * @throws shortbufferexception if the output buffer is too small to hold the result.
     */
    public final int update(byte[] input, int inoff, int inlen, byte[] output,
                            int outoff)
        throws shortbufferexception
    {
        if (output.length < getoutputsize(inlen))
        {
            throw new shortbufferexception("output");
        }
        byte[] out = update(input, inoff, inlen);
        system.arraycopy(out, 0, output, outoff, out.length);
        return out.length;
    }

    /**
     * finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     *
     * @param input the input buffer
     * @param inoff the offset where the input starts
     * @param inlen the input length
     * @return a new buffer with the result
     * @throws badpaddingexception if the ciphertext is invalid.
     */
    public abstract byte[] dofinal(byte[] input, int inoff, int inlen)
        throws badpaddingexception;

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
     * @throws badpaddingexception if the ciphertext is invalid.
     */
    public final int dofinal(byte[] input, int inoff, int inlen, byte[] output,
                             int outoff)
        throws shortbufferexception, badpaddingexception
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
     * compute the output size of an update() or dofinal() operation of a hybrid
     * asymmetric cipher in encryption mode when given input of the specified
     * length.
     *
     * @param inlen the length of the input
     * @return the output size
     */
    protected abstract int encryptoutputsize(int inlen);

    /**
     * compute the output size of an update() or dofinal() operation of a hybrid
     * asymmetric cipher in decryption mode when given input of the specified
     * length.
     *
     * @param inlen the length of the input
     * @return the output size
     */
    protected abstract int decryptoutputsize(int inlen);

    /**
     * initialize the asymmetrichybridcipher with a certain key for data
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
     * initialize the asymmetrichybridcipher with a certain key for data
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

}
