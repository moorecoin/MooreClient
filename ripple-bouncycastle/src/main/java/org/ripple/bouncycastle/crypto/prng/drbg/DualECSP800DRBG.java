package org.ripple.bouncycastle.crypto.prng.drbg;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.nist.nistnamedcurves;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.prng.entropysource;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecfieldelement;
import org.ripple.bouncycastle.math.ec.ecpoint;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.bigintegers;

/**
 * a sp800-90a dual ec drbg.
 */
public class dualecsp800drbg
    implements sp80090drbg
{
    /*
     * default p, q values for each curve
     */
    private static final biginteger p256_px = new biginteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    private static final biginteger p256_py = new biginteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    private static final biginteger p256_qx = new biginteger("c97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192", 16);
    private static final biginteger p256_qy = new biginteger("b28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046", 16);

    private static final biginteger p384_px = new biginteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16);
    private static final biginteger p384_py = new biginteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16);
    private static final biginteger p384_qx = new biginteger("8e722de3125bddb05580164bfe20b8b432216a62926c57502ceede31c47816edd1e89769124179d0b695106428815065", 16);
    private static final biginteger p384_qy = new biginteger("023b1660dd701d0839fd45eec36f9ee7b32e13b315dc02610aa1b636e346df671f790f84c5e09b05674dbb7e45c803dd", 16);

    private static final biginteger p521_px = new biginteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16);
    private static final biginteger p521_py = new biginteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16);
    private static final biginteger p521_qx = new biginteger("1b9fa3e518d683c6b65763694ac8efbaec6fab44f2276171a42726507dd08add4c3b3f4c1ebc5b1222ddba077f722943b24c3edfa0f85fe24d0c8c01591f0be6f63", 16);
    private static final biginteger p521_qy = new biginteger("1f3bdba585295d9a1110d1df1f9430ef8442c5018976ff3437ef91b81dc0b8132c8d5c39c32d0e004a3092b7d327c0e7a4d26d2c7b69b58f9066652911e457779de", 16);

    private static final long       reseed_max = 1l << (32 - 1);
    private static final int        max_additional_input = 1 << (13 - 1);
    private static final int        max_entropy_length = 1 << (13 - 1);
    private static final int        max_personalization_string = 1 << (13 -1);

    private digest                 _digest;
    private long                   _reseedcounter;
    private entropysource          _entropysource;
    private int                    _securitystrength;
    private int                    _seedlen;
    private int                    _outlen;
    private eccurve.fp             _curve;
    private ecpoint                _p;
    private ecpoint                _q;
    private byte[]                 _s;
    private int                    _slength;

    /**
     * construct a sp800-90a dual ec drbg.
     * <p>
     * minimum entropy requirement is the security strength requested.
     * </p>
     * @param digest source digest to use with the drb stream.
     * @param securitystrength security strength required (in bits)
     * @param entropysource source of entropy to use for seeding/reseeding.
     * @param personalizationstring personalization string to distinguish this drbg (may be null).
     * @param nonce nonce to further distinguish this drbg (may be null).
     */
    public dualecsp800drbg(digest digest, int securitystrength, entropysource entropysource, byte[] personalizationstring, byte[] nonce)
    {
        _digest = digest;
        _entropysource = entropysource;
        _securitystrength = securitystrength;

        if (utils.istoolarge(personalizationstring, max_personalization_string / 8))
        {
            throw new illegalargumentexception("personalization string too large");
        }

        if (entropysource.entropysize() < securitystrength || entropysource.entropysize() > max_entropy_length)
        {
            throw new illegalargumentexception("entropysource must provide between " + securitystrength + " and " + max_entropy_length + " bits");
        }

        byte[] entropy = entropysource.getentropy();
        byte[] seedmaterial = arrays.concatenate(entropy, nonce, personalizationstring);

        if (securitystrength <= 128)
        {
            if (utils.getmaxsecuritystrength(digest) < 128)
            {
                throw new illegalargumentexception("requested security strength is not supported by digest");
            }
            _seedlen = 256;
            _outlen = 240 / 8;
            _curve = (eccurve.fp)nistnamedcurves.getbyname("p-256").getcurve();
            _p = new ecpoint.fp(_curve, new ecfieldelement.fp(_curve.getq(), p256_px), new ecfieldelement.fp(_curve.getq(), p256_py));
            _q = new ecpoint.fp(_curve, new ecfieldelement.fp(_curve.getq(), p256_qx), new ecfieldelement.fp(_curve.getq(), p256_qy));
        }
        else if (securitystrength <= 192)
        {
            if (utils.getmaxsecuritystrength(digest) < 192)
            {
                throw new illegalargumentexception("requested security strength is not supported by digest");
            }
            _seedlen = 384;
            _outlen = 368 / 8;
            _curve = (eccurve.fp)nistnamedcurves.getbyname("p-384").getcurve();
            _p = new ecpoint.fp(_curve, new ecfieldelement.fp(_curve.getq(), p384_px), new ecfieldelement.fp(_curve.getq(), p384_py));
            _q = new ecpoint.fp(_curve, new ecfieldelement.fp(_curve.getq(), p384_qx), new ecfieldelement.fp(_curve.getq(), p384_qy));
        }
        else if (securitystrength <= 256)
        {
            if (utils.getmaxsecuritystrength(digest) < 256)
            {
                throw new illegalargumentexception("requested security strength is not supported by digest");
            }
            _seedlen = 521;
            _outlen = 504 / 8;
            _curve = (eccurve.fp)nistnamedcurves.getbyname("p-521").getcurve();
            _p = new ecpoint.fp(_curve, new ecfieldelement.fp(_curve.getq(), p521_px), new ecfieldelement.fp(_curve.getq(), p521_py));
            _q = new ecpoint.fp(_curve, new ecfieldelement.fp(_curve.getq(), p521_qx), new ecfieldelement.fp(_curve.getq(), p521_qy));
        }
        else
        {
            throw new illegalargumentexception("security strength cannot be greater than 256 bits");
        }

        _s = utils.hash_df(_digest, seedmaterial, _seedlen);
        _slength = _s.length;

        _reseedcounter = 0;
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
        int numberofbits = output.length*8;
        int m = output.length / _outlen;

        if (utils.istoolarge(additionalinput, max_additional_input / 8))
        {
            throw new illegalargumentexception("additional input too large");
        }

        if (_reseedcounter + m > reseed_max)
        {
            return -1;
        }

        if (predictionresistant)
        {   
            reseed(additionalinput);
            additionalinput = null;
        }

        if (additionalinput != null)
        {
            // note: we ignore the use of pad8 on the additional input as we mandate byte arrays for it.
            additionalinput = utils.hash_df(_digest, additionalinput, _seedlen);
        }

        for (int i = 0; i < m; i++)
        {
            biginteger t = new biginteger(1, xor(_s, additionalinput));

            _s = _p.multiply(t).getx().tobiginteger().tobytearray();

            //system.err.println("s: " + new string(hex.encode(_s)));

            byte[] r = _q.multiply(new biginteger(1, _s)).getx().tobiginteger().tobytearray();

            if (r.length > _outlen)
            {
                system.arraycopy(r, r.length - _outlen, output, i * _outlen, _outlen);
            }
            else
            {
                system.arraycopy(r, 0, output, i * _outlen + (_outlen - r.length), r.length);
            }

            //system.err.println("r: " + new string(hex.encode(r)));
            additionalinput = null;

            _reseedcounter++;
        }

        if (m * _outlen < output.length)
        {
            biginteger t = new biginteger(1, xor(_s, additionalinput));

            _s = _p.multiply(t).getx().tobiginteger().tobytearray();

            byte[] r = _q.multiply(new biginteger(1, _s)).getx().tobiginteger().tobytearray();

            system.arraycopy(r, 0, output, m * _outlen, output.length - (m * _outlen));
        }

        // need to preserve length of s as unsigned int.
        _s = bigintegers.asunsignedbytearray(_slength, _p.multiply(new biginteger(1, _s)).getx().tobiginteger());

        return numberofbits;
    }

    /**
      * reseed the drbg.
      *
      * @param additionalinput additional input to be added to the drbg in this step.
      */
    public void reseed(byte[] additionalinput)
    {
        if (utils.istoolarge(additionalinput, max_additional_input / 8))
        {
            throw new illegalargumentexception("additional input string too large");
        }

        byte[] entropy = _entropysource.getentropy();
        byte[] seedmaterial = arrays.concatenate(pad8(_s, _seedlen), entropy, additionalinput);

        _s = utils.hash_df(_digest, seedmaterial, _seedlen);

        _reseedcounter = 0;
    }

    private byte[] xor(byte[] a, byte[] b)
    {
        if (b == null)
        {
            return a;
        }

        byte[] rv = new byte[a.length];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = (byte)(a[i] ^ b[i]);
        }

        return rv;
    }

    // note: works in place
    private byte[] pad8(byte[] s, int seedlen)
    {
        if (seedlen % 8 == 0)
        {
            return s;
        }

        int shift = 8 - (seedlen % 8);
        int carry = 0;

        for (int i = s.length - 1; i >= 0; i--)
        {
            int b = s[i] & 0xff;
            s[i] = (byte)((b << shift) | (carry >> (8 - shift)));
            carry = b;
        }

        return s;
    }
}
