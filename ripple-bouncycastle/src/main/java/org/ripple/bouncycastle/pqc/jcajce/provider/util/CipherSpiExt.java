package org.ripple.bouncycastle.pqc.jcajce.provider.util;


import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.invalidparameterexception;
import java.security.key;
import java.security.nosuchalgorithmexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.cipherspi;
import javax.crypto.illegalblocksizeexception;
import javax.crypto.nosuchpaddingexception;
import javax.crypto.shortbufferexception;

/**
 * the cipherspiext class extends cipherspi.
 */
public abstract class cipherspiext
    extends cipherspi
{

    /**
     * constant specifying encrypt mode.
     */
    public static final int encrypt_mode = javax.crypto.cipher.encrypt_mode;

    /**
     * constant specifying decrypt mode.
     */
    public static final int decrypt_mode = javax.crypto.cipher.decrypt_mode;

    /**
     * the operation mode for this cipher ({@link #encrypt_mode} or
     * {@link #decrypt_mode}).
     */
    protected int opmode;

    // ****************************************************
    // jca adapter methods
    // ****************************************************

    /**
     * initialize this cipher object with a proper key and some random seed.
     * before a cipher object is ready for data processing, it has to be
     * initialized according to the desired cryptographic operation, which is
     * specified by the <tt>opmode</tt> parameter.
     * <p/>
     * if this cipher (including its underlying mode or padding scheme) requires
     * any random bytes, it will obtain them from <tt>random</tt>.
     * <p/>
     * note: if the mode needs an initialization vector, a blank array is used
     * in this case.
     *
     * @param opmode the operation mode ({@link #encrypt_mode} or
     *               {@link #decrypt_mode})
     * @param key    the key
     * @param random the random seed
     * @throws java.security.invalidkeyexception if the key is inappropriate for initializing this cipher.
     */
    protected final void engineinit(int opmode, java.security.key key,
                                    java.security.securerandom random)
        throws java.security.invalidkeyexception
    {

        try
        {
            engineinit(opmode, key,
                (java.security.spec.algorithmparameterspec)null, random);
        }
        catch (java.security.invalidalgorithmparameterexception e)
        {
            throw new invalidparameterexception(e.getmessage());
        }
    }

    /**
     * initialize this cipher with a key, a set of algorithm parameters, and a
     * source of randomness. the cipher is initialized for encryption or
     * decryption, depending on the value of <tt>opmode</tt>.
     * <p/>
     * if this cipher (including its underlying mode or padding scheme) requires
     * any random bytes, it will obtain them from <tt>random</tt>. note that
     * when a {@link blockcipher} object is initialized, it loses all
     * previously-acquired state. in other words, initializing a cipher is
     * equivalent to creating a new instance of that cipher and initializing it.
     * <p/>
     * note: if the mode needs an initialization vector, a try to retrieve it
     * from the algorithmparametersspec is made.
     *
     * @param opmode    the operation mode ({@link #encrypt_mode} or
     *                  {@link #decrypt_mode})
     * @param key       the key
     * @param algparams the algorithm parameters
     * @param random    the random seed
     * @throws java.security.invalidkeyexception if the key is inappropriate for initializing this block
     * cipher.
     * @throws java.security.invalidalgorithmparameterexception if the parameters are inappropriate for initializing this
     * block cipher.
     */
    protected final void engineinit(int opmode, java.security.key key,
                                    java.security.algorithmparameters algparams,
                                    java.security.securerandom random)
        throws java.security.invalidkeyexception,
        java.security.invalidalgorithmparameterexception
    {

        // if algparams are not specified, initialize without them
        if (algparams == null)
        {
            engineinit(opmode, key, random);
            return;
        }

        algorithmparameterspec paramspec = null;
        // xxx getting algorithmparameterspec from algorithmparameters

        engineinit(opmode, key, paramspec, random);
    }

    /**
     * initialize this cipher with a key, a set of algorithm parameters, and a
     * source of randomness. the cipher is initialized for one of the following
     * four operations: encryption, decryption, key wrapping or key unwrapping,
     * depending on the value of opmode. if this cipher (including its
     * underlying feedback or padding scheme) requires any random bytes (e.g.,
     * for parameter generation), it will get them from random. note that when a
     * cipher object is initialized, it loses all previously-acquired state. in
     * other words, initializing a cipher is equivalent to creating a new
     * instance of that cipher and initializing it.
     *
     * @param opmode   the operation mode ({@link #encrypt_mode} or
     *                 {@link #decrypt_mode})
     * @param key      the encryption key
     * @param params   the algorithm parameters
     * @param javarand the source of randomness
     * @throws java.security.invalidkeyexception if the given key is inappropriate for initializing this
     * cipher
     * @throws java.security.invalidalgorithmparameterexception if the given algorithm parameters are inappropriate for
     * this cipher, or if this cipher is being initialized for
     * decryption and requires algorithm parameters and the
     * parameters are null.
     */
    protected void engineinit(int opmode, java.security.key key,
                              java.security.spec.algorithmparameterspec params,
                              java.security.securerandom javarand)
        throws java.security.invalidkeyexception,
        java.security.invalidalgorithmparameterexception
    {

        if ((params != null) && !(params instanceof algorithmparameterspec))
        {
            throw new java.security.invalidalgorithmparameterexception();
        }

        if ((key == null) || !(key instanceof key))
        {
            throw new java.security.invalidkeyexception();
        }

        this.opmode = opmode;

        if (opmode == encrypt_mode)
        {
            securerandom flexirand = javarand;
            initencrypt((key)key, (algorithmparameterspec)params, flexirand);

        }
        else if (opmode == decrypt_mode)
        {
            initdecrypt((key)key, (algorithmparameterspec)params);

        }
    }

    /**
     * return the result of the last step of a multi-step en-/decryption
     * operation or the result of a single-step en-/decryption operation by
     * processing the given input data and any remaining buffered data. the data
     * to be processed is given in an input byte array. beginning at
     * inputoffset, only the first inputlen bytes are en-/decrypted, including
     * any buffered bytes of a previous update operation. if necessary, padding
     * is performed. the result is returned as a output byte array.
     *
     * @param input the byte array holding the data to be processed
     * @param inoff the offset indicating the start position within the input
     *              byte array
     * @param inlen the number of bytes to be processed
     * @return the byte array containing the en-/decrypted data
     * @throws javax.crypto.illegalblocksizeexception if the ciphertext length is not a multiple of the
     * blocklength.
     * @throws javax.crypto.badpaddingexception if unpadding is not possible.
     */
    protected final byte[] enginedofinal(byte[] input, int inoff, int inlen)
        throws javax.crypto.illegalblocksizeexception,
        javax.crypto.badpaddingexception
    {
        return dofinal(input, inoff, inlen);
    }

    /**
     * perform the last step of a multi-step en-/decryption operation or a
     * single-step en-/decryption operation by processing the given input data
     * and any remaining buffered data. the data to be processed is given in an
     * input byte array. beginning at inputoffset, only the first inputlen bytes
     * are en-/decrypted, including any buffered bytes of a previous update
     * operation. if necessary, padding is performed. the result is stored in
     * the given output byte array, beginning at outputoffset. the number of
     * bytes stored in this byte array are returned.
     *
     * @param input  the byte array holding the data to be processed
     * @param inoff  the offset indicating the start position within the input
     *               byte array
     * @param inlen  the number of bytes to be processed
     * @param output the byte array for holding the result
     * @param outoff the offset indicating the start position within the output
     *               byte array to which the en/decrypted data is written
     * @return the number of bytes stored in the output byte array
     * @throws javax.crypto.shortbufferexception if the output buffer is too short to hold the output.
     * @throws javax.crypto.illegalblocksizeexception if the ciphertext length is not a multiple of the
     * blocklength.
     * @throws javax.crypto.badpaddingexception if unpadding is not possible.
     */
    protected final int enginedofinal(byte[] input, int inoff, int inlen,
                                      byte[] output, int outoff)
        throws javax.crypto.shortbufferexception,
        javax.crypto.illegalblocksizeexception,
        javax.crypto.badpaddingexception
    {
        return dofinal(input, inoff, inlen, output, outoff);
    }

    /**
     * @return the block size (in bytes), or 0 if the underlying algorithm is
     *         not a block cipher
     */
    protected final int enginegetblocksize()
    {
        return getblocksize();
    }

    /**
     * return the key size of the given key object in bits.
     *
     * @param key the key object
     * @return the key size in bits of the given key object
     * @throws java.security.invalidkeyexception if key is invalid.
     */
    protected final int enginegetkeysize(java.security.key key)
        throws java.security.invalidkeyexception
    {
        if (!(key instanceof key))
        {
            throw new java.security.invalidkeyexception("unsupported key.");
        }
        return getkeysize((key)key);
    }

    /**
     * return the initialization vector. this is useful in the context of
     * password-based encryption or decryption, where the iv is derived from a
     * user-provided passphrase.
     *
     * @return the initialization vector in a new buffer, or <tt>null</tt> if
     *         the underlying algorithm does not use an iv, or if the iv has not
     *         yet been set.
     */
    protected final byte[] enginegetiv()
    {
        return getiv();
    }

    /**
     * return the length in bytes that an output buffer would need to be in
     * order to hold the result of the next update or dofinal operation, given
     * the input length inputlen (in bytes).
     * <p/>
     * this call takes into account any unprocessed (buffered) data from a
     * previous update call, and padding.
     * <p/>
     * the actual output length of the next update or dofinal call may be
     * smaller than the length returned by this method.
     *
     * @param inlen the input length (in bytes)
     * @return the required output buffer size (in bytes)
     */
    protected final int enginegetoutputsize(int inlen)
    {
        return getoutputsize(inlen);
    }

    /**
     * returns the parameters used with this cipher.
     * <p/>
     * the returned parameters may be the same that were used to initialize this
     * cipher, or may contain the default set of parameters or a set of randomly
     * generated parameters used by the underlying cipher implementation
     * (provided that the underlying cipher implementation uses a default set of
     * parameters or creates new parameters if it needs parameters but was not
     * initialized with any).
     *
     * @return the parameters used with this cipher, or null if this cipher does
     *         not use any parameters.
     */
    protected final java.security.algorithmparameters enginegetparameters()
    {
        // todo
        return null;
    }

    /**
     * set the mode of this cipher.
     *
     * @param modename the cipher mode
     * @throws java.security.nosuchalgorithmexception if neither the mode with the given name nor the default
     * mode can be found
     */
    protected final void enginesetmode(string modename)
        throws java.security.nosuchalgorithmexception
    {
        setmode(modename);
    }

    /**
     * set the padding scheme of this cipher.
     *
     * @param paddingname the padding scheme
     * @throws javax.crypto.nosuchpaddingexception if the requested padding scheme cannot be found.
     */
    protected final void enginesetpadding(string paddingname)
        throws javax.crypto.nosuchpaddingexception
    {
        setpadding(paddingname);
    }

    /**
     * return the result of the next step of a multi-step en-/decryption
     * operation. the data to be processed is given in an input byte array.
     * beginning at inputoffset, only the first inputlen bytes are
     * en-/decrypted. the result is returned as a byte array.
     *
     * @param input the byte array holding the data to be processed
     * @param inoff the offset indicating the start position within the input
     *              byte array
     * @param inlen the number of bytes to be processed
     * @return the byte array containing the en-/decrypted data
     */
    protected final byte[] engineupdate(byte[] input, int inoff, int inlen)
    {
        return update(input, inoff, inlen);
    }

    /**
     * perform the next step of a multi-step en-/decryption operation. the data
     * to be processed is given in an input byte array. beginning at
     * inputoffset, only the first inputlen bytes are en-/decrypted. the result
     * is stored in the given output byte array, beginning at outputoffset. the
     * number of bytes stored in this output byte array are returned.
     *
     * @param input  the byte array holding the data to be processed
     * @param inoff  the offset indicating the start position within the input
     *               byte array
     * @param inlen  the number of bytes to be processed
     * @param output the byte array for holding the result
     * @param outoff the offset indicating the start position within the output
     *               byte array to which the en-/decrypted data is written
     * @return the number of bytes that are stored in the output byte array
     * @throws javax.crypto.shortbufferexception if the output buffer is too short to hold the output.
     */
    protected final int engineupdate(final byte[] input, final int inoff,
                                     final int inlen, byte[] output, final int outoff)
        throws javax.crypto.shortbufferexception
    {
        return update(input, inoff, inlen, output, outoff);
    }

    /**
     * initialize this cipher with a key, a set of algorithm parameters, and a
     * source of randomness for encryption.
     * <p/>
     * if this cipher requires any algorithm parameters and paramspec is null,
     * the underlying cipher implementation is supposed to generate the required
     * parameters itself (using provider-specific default or random values) if
     * it is being initialized for encryption, and raise an
     * invalidalgorithmparameterexception if it is being initialized for
     * decryption. the generated parameters can be retrieved using
     * enginegetparameters or enginegetiv (if the parameter is an iv).
     * <p/>
     * if this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from random.
     * <p/>
     * note that when a {@link blockcipher} object is initialized, it loses all
     * previously-acquired state. in other words, initializing a cipher is
     * equivalent to creating a new instance of that cipher and initializing it.
     *
     * @param key          the encryption key
     * @param cipherparams the cipher parameters
     * @param random       the source of randomness
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * block cipher.
     * @throws invalidalgorithmparameterexception if the parameters are inappropriate for initializing this
     * block cipher.
     */
    public abstract void initencrypt(key key,
                                     algorithmparameterspec cipherparams, securerandom random)
        throws invalidkeyexception, invalidalgorithmparameterexception;

    /**
     * initialize this cipher with a key, a set of algorithm parameters, and a
     * source of randomness for decryption.
     * <p/>
     * if this cipher requires any algorithm parameters and paramspec is null,
     * the underlying cipher implementation is supposed to generate the required
     * parameters itself (using provider-specific default or random values) if
     * it is being initialized for encryption, and throw an
     * {@link invalidalgorithmparameterexception} if it is being initialized for
     * decryption. the generated parameters can be retrieved using
     * enginegetparameters or enginegetiv (if the parameter is an iv).
     * <p/>
     * if this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from random.
     * <p/>
     * note that when a {@link blockcipher} object is initialized, it loses all
     * previously-acquired state. in other words, initializing a cipher is
     * equivalent to creating a new instance of that cipher and initializing it.
     *
     * @param key          the encryption key
     * @param cipherparams the cipher parameters
     * @throws invalidkeyexception if the given key is inappropriate for initializing this
     * block cipher.
     * @throws invalidalgorithmparameterexception if the parameters are inappropriate for initializing this
     * block cipher.
     */
    public abstract void initdecrypt(key key,
                                     algorithmparameterspec cipherparams)
        throws invalidkeyexception,
        invalidalgorithmparameterexception;

    /**
     * @return the name of this cipher
     */
    public abstract string getname();

    /**
     * @return the block size (in bytes), or 0 if the underlying algorithm is
     *         not a block cipher
     */
    public abstract int getblocksize();

    /**
     * returns the length in bytes that an output buffer would need to be in
     * order to hold the result of the next update or dofinal operation, given
     * the input length inputlen (in bytes).
     * <p/>
     * this call takes into account any unprocessed (buffered) data from a
     * previous update call, and padding.
     * <p/>
     * the actual output length of the next update or dofinal call may be
     * smaller than the length returned by this method.
     *
     * @param inputlen the input length (in bytes)
     * @return the required output buffer size (in bytes)
     */
    public abstract int getoutputsize(int inputlen);

    /**
     * return the key size of the given key object in bits.
     *
     * @param key the key object
     * @return the key size in bits of the given key object
     * @throws invalidkeyexception if key is invalid.
     */
    public abstract int getkeysize(key key)
        throws invalidkeyexception;

    /**
     * returns the parameters used with this cipher.
     * <p/>
     * the returned parameters may be the same that were used to initialize this
     * cipher, or may contain the default set of parameters or a set of randomly
     * generated parameters used by the underlying cipher implementation
     * (provided that the underlying cipher implementation uses a default set of
     * parameters or creates new parameters if it needs parameters but was not
     * initialized with any).
     *
     * @return the parameters used with this cipher, or null if this cipher does
     *         not use any parameters.
     */
    public abstract algorithmparameterspec getparameters();

    /**
     * return the initialization vector. this is useful in the context of
     * password-based encryption or decryption, where the iv is derived from a
     * user-provided passphrase.
     *
     * @return the initialization vector in a new buffer, or <tt>null</tt> if
     *         the underlying algorithm does not use an iv, or if the iv has not
     *         yet been set.
     */
    public abstract byte[] getiv();

    /**
     * set the mode of this cipher.
     *
     * @param mode the cipher mode
     * @throws nosuchmodeexception if the requested mode cannot be found.
     */
    protected abstract void setmode(string mode)
        throws nosuchalgorithmexception;

    /**
     * set the padding mechanism of this cipher.
     *
     * @param padding the padding mechanism
     * @throws nosuchpaddingexception if the requested padding scheme cannot be found.
     */
    protected abstract void setpadding(string padding)
        throws nosuchpaddingexception;

    /**
     * continue a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     *
     * @param input the input buffer
     * @return a new buffer with the result (maybe an empty byte array)
     */
    public final byte[] update(byte[] input)
    {
        return update(input, 0, input.length);
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
    public abstract int update(byte[] input, int inoff, int inlen,
                               byte[] output, int outoff)
        throws shortbufferexception;

    /**
     * finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     *
     * @return a new buffer with the result
     * @throws illegalblocksizeexception if this cipher is a block cipher and the total input
     * length is not a multiple of the block size (for
     * encryption when no padding is used or for decryption).
     * @throws badpaddingexception if this cipher is a block cipher and unpadding fails.
     */
    public final byte[] dofinal()
        throws illegalblocksizeexception,
        badpaddingexception
    {
        return dofinal(null, 0, 0);
    }

    /**
     * finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     *
     * @param input the input buffer
     * @return a new buffer with the result
     * @throws illegalblocksizeexception if this cipher is a block cipher and the total input
     * length is not a multiple of the block size (for
     * encryption when no padding is used or for decryption).
     * @throws badpaddingexception if this cipher is a block cipher and unpadding fails.
     */
    public final byte[] dofinal(byte[] input)
        throws illegalblocksizeexception,
        badpaddingexception
    {
        return dofinal(input, 0, input.length);
    }

    /**
     * finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     *
     * @param input the input buffer
     * @param inoff the offset where the input starts
     * @param inlen the input length
     * @return a new buffer with the result
     * @throws illegalblocksizeexception if this cipher is a block cipher and the total input
     * length is not a multiple of the block size (for
     * encryption when no padding is used or for decryption).
     * @throws badpaddingexception if this cipher is a block cipher and unpadding fails.
     */
    public abstract byte[] dofinal(byte[] input, int inoff, int inlen)
        throws illegalblocksizeexception, badpaddingexception;

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
     * @throws illegalblocksizeexception if this cipher is a block cipher and the total input
     * length is not a multiple of the block size (for
     * encryption when no padding is used or for decryption).
     * @throws badpaddingexception if this cipher is a block cipher and unpadding fails.
     */
    public abstract int dofinal(byte[] input, int inoff, int inlen,
                                byte[] output, int outoff)
        throws shortbufferexception,
        illegalblocksizeexception, badpaddingexception;

}
