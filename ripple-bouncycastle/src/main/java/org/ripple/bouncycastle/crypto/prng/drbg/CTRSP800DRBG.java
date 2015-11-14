package org.ripple.bouncycastle.crypto.prng.drbg;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.prng.entropysource;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * a sp800-90a ctr drbg.
 */
public class ctrsp800drbg
    implements sp80090drbg
{
    private static final long       tdea_reseed_max = 1l << (32 - 1);
    private static final long       aes_reseed_max = 1l << (48 - 1);
    private static final int        tdea_max_bits_request = 1 << (13 - 1);
    private static final int        aes_max_bits_request = 1 << (19 - 1);

    private entropysource          _entropysource;
    private blockcipher           _engine;
    private int                   _keysizeinbits;
    private int                   _seedlength;
    
    // internal state
    private byte[]                _key;
    private byte[]                _v;
    private long                  _reseedcounter = 0;
    private boolean               _istdea = false;

    /**
     * construct a sp800-90a ctr drbg.
     * <p>
     * minimum entropy requirement is the security strength requested.
     * </p>
     * @param engine underlying block cipher to use to support drbg
     * @param keysizeinbits size of the key to use with the block cipher.
     * @param securitystrength security strength required (in bits)
     * @param entropysource source of entropy to use for seeding/reseeding.
     * @param personalizationstring personalization string to distinguish this drbg (may be null).
     * @param nonce nonce to further distinguish this drbg (may be null).
     */
    public ctrsp800drbg(blockcipher engine, int keysizeinbits, int securitystrength, entropysource entropysource, byte[] personalizationstring, byte[] nonce)
    {
        _entropysource = entropysource;
        _engine = engine;     
        
        _keysizeinbits = keysizeinbits;
        _seedlength = keysizeinbits + engine.getblocksize() * 8;
        _istdea = istdea(engine);

        if (securitystrength > 256)
        {
            throw new illegalargumentexception("requested security strength is not supported by the derivation function");
        }

        if (getmaxsecuritystrength(engine, keysizeinbits) < securitystrength)
        {
            throw new illegalargumentexception("requested security strength is not supported by block cipher and key size");
        }

        if (entropysource.entropysize() < securitystrength)
        {
            throw new illegalargumentexception("not enough entropy for security strength required");
        }

        byte[] entropy = entropysource.getentropy();  // get_entropy_input

        ctr_drbg_instantiate_algorithm(entropy, nonce, personalizationstring);
    }

    private void ctr_drbg_instantiate_algorithm(byte[] entropy, byte[] nonce,
            byte[] personalisationstring)
    {
        byte[] seedmaterial = arrays.concatenate(entropy, nonce, personalisationstring);
        byte[] seed = block_cipher_df(seedmaterial, _seedlength);

        int outlen = _engine.getblocksize();

        _key = new byte[(_keysizeinbits + 7) / 8];
        _v = new byte[outlen];

         // _key & _v are modified by this call
        ctr_drbg_update(seed, _key, _v); 

        _reseedcounter = 1;
    }

    private void ctr_drbg_update(byte[] seed, byte[] key, byte[] v)
    {
        byte[] temp = new byte[seed.length];
        byte[] outputblock = new byte[_engine.getblocksize()];
        
        int i=0;
        int outlen = _engine.getblocksize();

        _engine.init(true, new keyparameter(expandkey(key)));
        while (i*outlen < seed.length)
        {
            addoneto(v);
            _engine.processblock(v, 0, outputblock, 0);

            int bytestocopy = ((temp.length - i * outlen) > outlen)
                    ? outlen : (temp.length - i * outlen);
            
            system.arraycopy(outputblock, 0, temp, i * outlen, bytestocopy);
            ++i;
        }

        xor(temp, seed, temp, 0);

        system.arraycopy(temp, 0, key, 0, key.length);
        system.arraycopy(temp, key.length, v, 0, v.length);
    }
    
    private void ctr_drbg_reseed_algorithm(entropysource entropy, byte[] additionalinput) 
    {
        byte[] seedmaterial = arrays.concatenate(entropy.getentropy(), additionalinput);

        seedmaterial = block_cipher_df(seedmaterial, _seedlength);

        ctr_drbg_update(seedmaterial, _key, _v);

        _reseedcounter = 1;
    }

    private void xor(byte[] out, byte[] a, byte[] b, int boff)
    {
        for (int i=0; i< out.length; i++) 
        {
            out[i] = (byte)(a[i] ^ b[i+boff]);
        }
    }
    
    private void addoneto(byte[] longer)
    {
        int carry = 1;
        for (int i = 1; i <= longer.length; i++) // warning
        {
            int res = (longer[longer.length - i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length - i] = (byte)res;
        }
    } 
    
    // -- internal state migration ---
    
    private static final byte[] k_bits = hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    // 1. if (number_of_bits_to_return > max_number_of_bits), then return an
    // error_flag.
    // 2. l = len (input_string)/8.
    // 3. n = number_of_bits_to_return/8.
    // comment: l is the bitstring represention of
    // the integer resulting from len (input_string)/8.
    // l shall be represented as a 32-bit integer.
    //
    // comment : n is the bitstring represention of
    // the integer resulting from
    // number_of_bits_to_return/8. n shall be
    // represented as a 32-bit integer.
    //
    // 4. s = l || n || input_string || 0x80.
    // 5. while (len (s) mod outlen)
    // comment : pad s with zeros, if necessary.
    // 0, s = s || 0x00.
    //
    // comment : compute the starting value.
    // 6. temp = the null string.
    // 7. i = 0.
    // 8. k = leftmost keylen bits of 0x00010203...1d1e1f.
    // 9. while len (temp) < keylen + outlen, do
    //
    // iv = i || 0outlen - len (i).
    //
    // 9.1
    //
    // temp = temp || bcc (k, (iv || s)).
    //
    // 9.2
    //
    // i = i + 1.
    //
    // 9.3
    //
    // comment : i shall be represented as a 32-bit
    // integer, i.e., len (i) = 32.
    //
    // comment: the 32-bit integer represenation of
    // i is padded with zeros to outlen bits.
    //
    // comment: compute the requested number of
    // bits.
    //
    // 10. k = leftmost keylen bits of temp.
    //
    // 11. x = next outlen bits of temp.
    //
    // 12. temp = the null string.
    //
    // 13. while len (temp) < number_of_bits_to_return, do
    //
    // 13.1 x = block_encrypt (k, x).
    //
    // 13.2 temp = temp || x.
    //
    // 14. requested_bits = leftmost number_of_bits_to_return of temp.
    //
    // 15. return success and requested_bits.
    private byte[] block_cipher_df(byte[] inputstring, int bitlength)
    {
        int outlen = _engine.getblocksize();
        int l = inputstring.length; // already in bytes
        int n = bitlength / 8;
        // 4 s = l || n || inputstring || 0x80
        int slen = 4 + 4 + l + 1;
        int blocklen = ((slen + outlen - 1) / outlen) * outlen;
        byte[] s = new byte[blocklen];
        copyinttobytearray(s, l, 0);
        copyinttobytearray(s, n, 4);
        system.arraycopy(inputstring, 0, s, 8, l);
        s[8 + l] = (byte)0x80;
        // s already padded with zeros

        byte[] temp = new byte[_keysizeinbits / 8 + outlen];
        byte[] bccout = new byte[outlen];

        byte[] iv = new byte[outlen]; 
        
        int i = 0;
        byte[] k = new byte[_keysizeinbits / 8];
        system.arraycopy(k_bits, 0, k, 0, k.length);

        while (i*outlen*8 < _keysizeinbits + outlen *8)
        {
            copyinttobytearray(iv, i, 0);
            bcc(bccout, k, iv, s);

            int bytestocopy = ((temp.length - i * outlen) > outlen)
                    ? outlen
                    : (temp.length - i * outlen);
            
            system.arraycopy(bccout, 0, temp, i * outlen, bytestocopy);
            ++i;
        }

        byte[] x = new byte[outlen];
        system.arraycopy(temp, 0, k, 0, k.length);
        system.arraycopy(temp, k.length, x, 0, x.length);

        temp = new byte[bitlength / 2];

        i = 0;
        _engine.init(true, new keyparameter(expandkey(k)));

        while (i * outlen < temp.length)
        {
            _engine.processblock(x, 0, x, 0);

            int bytestocopy = ((temp.length - i * outlen) > outlen)
                    ? outlen
                    : (temp.length - i * outlen);

            system.arraycopy(x, 0, temp, i * outlen, bytestocopy);
            i++;
        }

        return temp;
    }

    /*
    * 1. chaining_value = 0^outlen    
    *    . comment: set the first chaining value to outlen zeros.
    * 2. n = len (data)/outlen.
    * 3. starting with the leftmost bits of data, split the data into n blocks of outlen bits 
    *    each, forming block(1) to block(n). 
    * 4. for i = 1 to n do
    * 4.1 input_block = chaining_value ^ block(i) .
    * 4.2 chaining_value = block_encrypt (key, input_block).
    * 5. output_block = chaining_value.
    * 6. return output_block. 
     */
    private void bcc(byte[] bccout, byte[] k, byte[] iv, byte[] data)
    {
        int outlen = _engine.getblocksize();
        byte[] chainingvalue = new byte[outlen]; // initial values = 0
        int n = data.length / outlen;

        byte[] inputblock = new byte[outlen];

        _engine.init(true, new keyparameter(expandkey(k)));

        _engine.processblock(iv, 0, chainingvalue, 0);

        for (int i = 0; i < n; i++)
        {
            xor(inputblock, chainingvalue, data, i*outlen);
            _engine.processblock(inputblock, 0, chainingvalue, 0);
        }

        system.arraycopy(chainingvalue, 0, bccout, 0, bccout.length);
    }

    private void copyinttobytearray(byte[] buf, int value, int offset)
    {
        buf[offset + 0] = ((byte)(value >> 24));
        buf[offset + 1] = ((byte)(value >> 16));
        buf[offset + 2] = ((byte)(value >> 8));
        buf[offset + 3] = ((byte)(value));
    }

    /**
     * populate a passed in array with random data.
     *
     * @param output output array for generated bits.
     * @param additionalinput additional input to be added to the drbg in this step.
     * @param predictionresistant true if a reseed should be forced, false otherwise.
     *
     * @return number of bits generated, -1 if a reseed required.
     */
    public int generate(byte[] output, byte[] additionalinput, boolean predictionresistant)
    {
        if (_istdea)
        {
            if (_reseedcounter > tdea_reseed_max)
            {
                return -1;
            }

            if (utils.istoolarge(output, tdea_max_bits_request / 8))
            {
                throw new illegalargumentexception("number of bits per request limited to " + tdea_max_bits_request);
            }
        }
        else
        {
            if (_reseedcounter > aes_reseed_max)
            {
                return -1;
            }

            if (utils.istoolarge(output, aes_max_bits_request / 8))
            {
                throw new illegalargumentexception("number of bits per request limited to " + aes_max_bits_request);
            }
        }

        if (predictionresistant)
        {
            ctr_drbg_reseed_algorithm(_entropysource, additionalinput);
            additionalinput = null;
        }

        if (additionalinput != null)
        {
            additionalinput = block_cipher_df(additionalinput, _seedlength);
            ctr_drbg_update(additionalinput, _key, _v);
        }
        else
        {
            additionalinput = new byte[_seedlength];
        }

        byte[] out = new byte[_v.length];

        _engine.init(true, new keyparameter(expandkey(_key)));

        for (int i = 0; i < output.length / out.length; i++)
        {
            addoneto(_v);

            _engine.processblock(_v, 0, out, 0);

            int bytestocopy = ((output.length - i * out.length) > out.length)
                    ? out.length
                    : (output.length - i * _v.length);

            system.arraycopy(out, 0, output, i * out.length, bytestocopy);
        }

        ctr_drbg_update(additionalinput, _key, _v);

        _reseedcounter++;

        return output.length * 8;
    }

    /**
      * reseed the drbg.
      *
      * @param additionalinput additional input to be added to the drbg in this step.
      */
    public void reseed(byte[] additionalinput)
    {
        ctr_drbg_reseed_algorithm(_entropysource, additionalinput);
    }

    private boolean istdea(blockcipher cipher)
    {
        return cipher.getalgorithmname().equals("desede") || cipher.getalgorithmname().equals("tdea");
    }

    private int getmaxsecuritystrength(blockcipher cipher, int keysizeinbits)
    {
        if (istdea(cipher) && keysizeinbits == 168)
        {
            return 112;
        }
        if (cipher.getalgorithmname().equals("aes"))
        {
            return keysizeinbits;
        }

        return -1;
    }

    byte[] expandkey(byte[] key)
    {
        if (_istdea)
        {
            // expand key to 192 bits.
            byte[] tmp = new byte[24];

            padkey(key, 0, tmp, 0);
            padkey(key, 7, tmp, 8);
            padkey(key, 14, tmp, 16);

            return tmp;
        }
        else
        {
            return key;
        }
    }

    /**
     * pad out a key for tdea, setting odd parity for each byte.
     *
     * @param keymaster
     * @param keyoff
     * @param tmp
     * @param tmpoff
     */
    private void padkey(byte[] keymaster, int keyoff, byte[] tmp, int tmpoff)
    {
        tmp[tmpoff + 0] = (byte)(keymaster[keyoff + 0] & 0xfe);
        tmp[tmpoff + 1] = (byte)((keymaster[keyoff + 0] << 7) | ((keymaster[keyoff + 1] & 0xfc) >>> 1));
        tmp[tmpoff + 2] = (byte)((keymaster[keyoff + 1] << 6) | ((keymaster[keyoff + 2] & 0xf8) >>> 2));
        tmp[tmpoff + 3] = (byte)((keymaster[keyoff + 2] << 5) | ((keymaster[keyoff + 3] & 0xf0) >>> 3));
        tmp[tmpoff + 4] = (byte)((keymaster[keyoff + 3] << 4) | ((keymaster[keyoff + 4] & 0xe0) >>> 4));
        tmp[tmpoff + 5] = (byte)((keymaster[keyoff + 4] << 3) | ((keymaster[keyoff + 5] & 0xc0) >>> 5));
        tmp[tmpoff + 6] = (byte)((keymaster[keyoff + 5] << 2) | ((keymaster[keyoff + 6] & 0x80) >>> 6));
        tmp[tmpoff + 7] = (byte)(keymaster[keyoff + 6] << 1);

        for (int i = tmpoff; i <= tmpoff + 7; i++)
        {
            int b = tmp[i];
            tmp[i] = (byte)((b & 0xfe) |
                            ((((b >> 1) ^
                            (b >> 2) ^
                            (b >> 3) ^
                            (b >> 4) ^
                            (b >> 5) ^
                            (b >> 6) ^
                            (b >> 7)) ^ 0x01) & 0x01));
        }
    }
}
