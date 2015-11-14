package org.ripple.bouncycastle.crypto.prng.drbg;

import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.prng.entropysource;
import org.ripple.bouncycastle.util.arrays;

/**
 * a sp800-90a hmac drbg.
 */
public class hmacsp800drbg
    implements sp80090drbg
{
    private final static long       reseed_max = 1l << (48 - 1);
    private final static int        max_bits_request = 1 << (19 - 1);

    private byte[] _k;
    private byte[] _v;
    private long   _reseedcounter;
    private entropysource _entropysource;
    private mac _hmac;

    /**
     * construct a sp800-90a hash drbg.
     * <p>
     * minimum entropy requirement is the security strength requested.
     * </p>
     * @param hmac hash mac to base the drbg on.
     * @param securitystrength security strength required (in bits)
     * @param entropysource source of entropy to use for seeding/reseeding.
     * @param personalizationstring personalization string to distinguish this drbg (may be null).
     * @param nonce nonce to further distinguish this drbg (may be null).
     */
    public hmacsp800drbg(mac hmac, int securitystrength, entropysource entropysource, byte[] personalizationstring, byte[] nonce)
    {
        if (securitystrength > utils.getmaxsecuritystrength(hmac))
        {
            throw new illegalargumentexception("requested security strength is not supported by the derivation function");
        }

        if (entropysource.entropysize() < securitystrength)
        {
            throw new illegalargumentexception("not enough entropy for security strength required");
        }

        _entropysource = entropysource;
        _hmac = hmac;

        byte[] entropy = entropysource.getentropy();
        byte[] seedmaterial = arrays.concatenate(entropy, nonce, personalizationstring);

        _k = new byte[hmac.getmacsize()];
        _v = new byte[_k.length];
        arrays.fill(_v, (byte)1);

        hmac_drbg_update(seedmaterial);

        _reseedcounter = 1;
    }

    private void hmac_drbg_update(byte[] seedmaterial)
    {
        hmac_drbg_update_func(seedmaterial, (byte)0x00);
        if (seedmaterial != null)
        {
            hmac_drbg_update_func(seedmaterial, (byte)0x01);
        }
    }

    private void hmac_drbg_update_func(byte[] seedmaterial, byte vvalue)
    {
        _hmac.init(new keyparameter(_k));

        _hmac.update(_v, 0, _v.length);
        _hmac.update(vvalue);

        if (seedmaterial != null)
        {
            _hmac.update(seedmaterial, 0, seedmaterial.length);
        }

        _hmac.dofinal(_k, 0);

        _hmac.init(new keyparameter(_k));
        _hmac.update(_v, 0, _v.length);

        _hmac.dofinal(_v, 0);
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
        int numberofbits = output.length * 8;

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
            hmac_drbg_update(additionalinput);
        }

        // 3.
        byte[] rv = new byte[output.length];

        int m = output.length / _v.length;

        _hmac.init(new keyparameter(_k));

        for (int i = 0; i < m; i++)
        {
            _hmac.update(_v, 0, _v.length);
            _hmac.dofinal(_v, 0);

            system.arraycopy(_v, 0, rv, i * _v.length, _v.length);
        }

        if (m * _v.length < rv.length)
        {
            _hmac.update(_v, 0, _v.length);
            _hmac.dofinal(_v, 0);

            system.arraycopy(_v, 0, rv, m * _v.length, rv.length - (m * _v.length));
        }

        hmac_drbg_update(additionalinput);

        _reseedcounter++;

        system.arraycopy(rv, 0, output, 0, output.length);

        return numberofbits;
    }

    /**
      * reseed the drbg.
      *
      * @param additionalinput additional input to be added to the drbg in this step.
      */
    public void reseed(byte[] additionalinput)
    {
        byte[] entropy = _entropysource.getentropy();
        byte[] seedmaterial = arrays.concatenate(entropy, additionalinput);

        hmac_drbg_update(seedmaterial);

        _reseedcounter = 1;
    }
}
