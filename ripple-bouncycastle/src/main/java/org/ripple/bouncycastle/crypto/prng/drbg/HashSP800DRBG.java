package org.ripple.bouncycastle.crypto.prng.drbg;

import java.util.hashtable;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.prng.entropysource;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;

/**
 * a sp800-90a hash drbg.
 */
public class hashsp800drbg
    implements sp80090drbg
{
    private final static byte[]     one = { 0x01 };

    private final static long       reseed_max = 1l << (48 - 1);
    private final static int        max_bits_request = 1 << (19 - 1);

    private final static hashtable  seedlens = new hashtable();

    static
    {
        seedlens.put("sha-1", integers.valueof(440));
        seedlens.put("sha-224", integers.valueof(440));
        seedlens.put("sha-256", integers.valueof(440));
        seedlens.put("sha-512/256", integers.valueof(440));
        seedlens.put("sha-512/224", integers.valueof(440));
        seedlens.put("sha-384", integers.valueof(888));
        seedlens.put("sha-512", integers.valueof(888));
    }

    private digest        _digest;
    private byte[]        _v;
    private byte[]        _c;
    private long          _reseedcounter;
    private entropysource _entropysource;
    private int           _securitystrength;
    private int           _seedlength;

    /**
     * construct a sp800-90a hash drbg.
     * <p>
     * minimum entropy requirement is the security strength requested.
     * </p>
     * @param digest  source digest to use for drb stream.
     * @param securitystrength security strength required (in bits)
     * @param entropysource source of entropy to use for seeding/reseeding.
     * @param personalizationstring personalization string to distinguish this drbg (may be null).
     * @param nonce nonce to further distinguish this drbg (may be null).
     */
    public hashsp800drbg(digest digest, int securitystrength, entropysource entropysource, byte[] personalizationstring, byte[] nonce)
    {
        if (securitystrength > utils.getmaxsecuritystrength(digest))
        {
            throw new illegalargumentexception("requested security strength is not supported by the derivation function");
        }

        if (entropysource.entropysize() < securitystrength)
        {
            throw new illegalargumentexception("not enough entropy for security strength required");
        }

        _digest = digest;
        _entropysource = entropysource;
        _securitystrength = securitystrength;
        _seedlength = ((integer)seedlens.get(digest.getalgorithmname())).intvalue();

        // 1. seed_material = entropy_input || nonce || personalization_string.
        // 2. seed = hash_df (seed_material, seedlen).
        // 3. v = seed.
        // 4. c = hash_df ((0x00 || v), seedlen). comment: preceed v with a byte
        // of zeros.
        // 5. reseed_counter = 1.
        // 6. return v, c, and reseed_counter as the initial_working_state

        byte[] entropy = entropysource.getentropy();
        byte[] seedmaterial = arrays.concatenate(entropy, nonce, personalizationstring);
        byte[] seed = utils.hash_df(_digest, seedmaterial, _seedlength);

        _v = seed;
        byte[] subv = new byte[_v.length + 1];
        system.arraycopy(_v, 0, subv, 1, _v.length);
        _c = utils.hash_df(_digest, subv, _seedlength);

        _reseedcounter = 1;
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
        // 1. if reseed_counter > reseed_interval, then return an indication that a
        // reseed is required.
        // 2. if (additional_input != null), then do
        // 2.1 w = hash (0x02 || v || additional_input).
        // 2.2 v = (v + w) mod 2^seedlen
        // .
        // 3. (returned_bits) = hashgen (requested_number_of_bits, v).
        // 4. h = hash (0x03 || v).
        // 5. v = (v + h + c + reseed_counter) mod 2^seedlen
        // .
        // 6. reseed_counter = reseed_counter + 1.
        // 7. return success, returned_bits, and the new values of v, c, and
        // reseed_counter for the new_working_state.
        int numberofbits = output.length*8;

        if (numberofbits > max_bits_request)
        {
            throw new illegalargumentexception("number of bits per request limited to " + max_bits_request);
        }

        if (_reseedcounter > reseed_max)
        {
            return -1;
        }

        if (predictionresistant)
        {   
            reseed(additionalinput);
            additionalinput = null;
        }

        // 2.
        if (additionalinput != null)
        {
            byte[] newinput = new byte[1 + _v.length + additionalinput.length];
            newinput[0] = 0x02;
            system.arraycopy(_v, 0, newinput, 1, _v.length);
            // todo: inoff / inlength
            system.arraycopy(additionalinput, 0, newinput, 1 + _v.length, additionalinput.length);
            byte[] w = hash(newinput);

            addto(_v, w);
        }
        
        // 3.
        byte[] rv = hashgen(_v, numberofbits);
        
        // 4.
        byte[] subh = new byte[_v.length + 1];
        system.arraycopy(_v, 0, subh, 1, _v.length);
        subh[0] = 0x03;
        
        byte[] h = hash(subh);
        
        // 5.
        addto(_v, h);
        addto(_v, _c);
        byte[] c = new byte[4];
        c[0] = (byte)(_reseedcounter >> 24);
        c[1] = (byte)(_reseedcounter >> 16);
        c[2] = (byte)(_reseedcounter >> 8);
        c[3] = (byte)_reseedcounter;
        
        addto(_v, c);

        _reseedcounter++;

        system.arraycopy(rv, 0, output, 0, output.length);

        return numberofbits;
    }

    // this will always add the shorter length byte array mathematically to the
    // longer length byte array.
    // be careful....
    private void addto(byte[] longer, byte[] shorter)
    {
        int carry = 0;
        for (int i=1;i <= shorter.length; i++) // warning
        {
            int res = (longer[longer.length-i] & 0xff) + (shorter[shorter.length-i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length-i] = (byte)res;
        }
        
        for (int i=shorter.length+1;i <= longer.length; i++) // warning
        {
            int res = (longer[longer.length-i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length-i] = (byte)res;
        }
    }

    /**
      * reseed the drbg.
      *
      * @param additionalinput additional input to be added to the drbg in this step.
      */
    public void reseed(byte[] additionalinput)
    {
        // 1. seed_material = 0x01 || v || entropy_input || additional_input.
        //
        // 2. seed = hash_df (seed_material, seedlen).
        //
        // 3. v = seed.
        //
        // 4. c = hash_df ((0x00 || v), seedlen).
        //
        // 5. reseed_counter = 1.
        //
        // 6. return v, c, and reseed_counter for the new_working_state.
        //
        // comment: precede with a byte of all zeros.
        byte[] entropy = _entropysource.getentropy();
        byte[] seedmaterial = arrays.concatenate(one, _v, entropy, additionalinput);
        byte[] seed = utils.hash_df(_digest, seedmaterial, _seedlength);

        _v = seed;
        byte[] subv = new byte[_v.length + 1];
        subv[0] = 0x00;
        system.arraycopy(_v, 0, subv, 1, _v.length);
        _c = utils.hash_df(_digest, subv, _seedlength);

        _reseedcounter = 1;
    }
    
    private byte[] hash(byte[] input)
    {
        _digest.update(input, 0, input.length);
        byte[] hash = new byte[_digest.getdigestsize()];
        _digest.dofinal(hash, 0);
        return hash;
    }
    
    // 1. m = [requested_number_of_bits / outlen]
    // 2. data = v.
    // 3. w = the null string.
    // 4. for i = 1 to m
    // 4.1 wi = hash (data).
    // 4.2 w = w || wi.
    // 4.3 data = (data + 1) mod 2^seedlen
    // .
    // 5. returned_bits = leftmost (requested_no_of_bits) bits of w.
    private byte[] hashgen(byte[] input, int lengthinbits)
    {
        int digestsize = _digest.getdigestsize();
        int m = (lengthinbits / 8) / digestsize;

        byte[] data = new byte[input.length];
        system.arraycopy(input, 0, data, 0, input.length);

        byte[] w = new byte[lengthinbits / 8];

        byte[] dig;
        for (int i = 0; i <= m; i++)
        {
            dig = hash(data);

            int bytestocopy = ((w.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (w.length - i * dig.length);
            system.arraycopy(dig, 0, w, i * dig.length, bytestocopy);

            addto(data, one);
        }

        return w;
    }    
}