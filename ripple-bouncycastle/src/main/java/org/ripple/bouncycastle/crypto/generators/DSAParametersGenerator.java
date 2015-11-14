package org.ripple.bouncycastle.crypto.generators;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.params.dsaparametergenerationparameters;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsavalidationparameters;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.bigintegers;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * generate suitable parameters for dsa, in line with fips 186-2, or fips 186-3.
 */
public class dsaparametersgenerator
{
    private digest          digest;
    private int             l, n;
    private int             certainty;
    private securerandom    random;

    private static final biginteger zero = biginteger.valueof(0);
    private static final biginteger one = biginteger.valueof(1);
    private static final biginteger two = biginteger.valueof(2);

    private boolean use186_3;
    private int usageindex;

    public dsaparametersgenerator()
    {
        this(new sha1digest());
    }

    public dsaparametersgenerator(digest digest)
    {
        this.digest = digest;
    }

    /**
     * initialise the key generator.
     *
     * @param size size of the key (range 2^512 -> 2^1024 - 64 bit increments)
     * @param certainty measure of robustness of prime (for fips 186-2 compliance this should be at least 80).
     * @param random random byte source.
     */
    public void init(
        int             size,
        int             certainty,
        securerandom    random)
    {
        this.use186_3 = false;
        this.l = size;
        this.n = getdefaultn(size);
        this.certainty = certainty;
        this.random = random;
    }

    /**
     * initialise the key generator for dsa 2.
     * <p>
     *     use this init method if you need to generate parameters for dsa 2 keys.
     * </p>
     *
     * @param params  dsa 2 key generation parameters.
     */
    public void init(
        dsaparametergenerationparameters params)
    {
        // todo should we enforce the minimum 'certainty' values as per c.3 table c.1?
        this.use186_3 = true;
        this.l = params.getl();
        this.n = params.getn();
        this.certainty = params.getcertainty();
        this.random = params.getrandom();
        this.usageindex = params.getusageindex();

        if ((l < 1024 || l > 3072) || l % 1024 != 0)
        {
            throw new illegalargumentexception("l values must be between 1024 and 3072 and a multiple of 1024");
        }
        else if (l == 1024 && n != 160)
        {
            throw new illegalargumentexception("n must be 160 for l = 1024");
        }
        else if (l == 2048 && (n != 224 && n != 256))
        {
            throw new illegalargumentexception("n must be 224 or 256 for l = 2048");
        }
        else if (l == 3072 && n != 256)
        {
            throw new illegalargumentexception("n must be 256 for l = 3072");
        }

        if (digest.getdigestsize() * 8 < n)
        {
            throw new illegalstateexception("digest output size too small for value of n");
        }
    }

    /**
     * which generates the p and g values from the given parameters,
     * returning the dsaparameters object.
     * <p>
     * note: can take a while...
     */
    public dsaparameters generateparameters()
    {
        return (use186_3)
            ? generateparameters_fips186_3()
            : generateparameters_fips186_2();
    }

    private dsaparameters generateparameters_fips186_2()
    {
        byte[]          seed = new byte[20];
        byte[]          part1 = new byte[20];
        byte[]          part2 = new byte[20];
        byte[]          u = new byte[20];
        int             n = (l - 1) / 160;
        byte[]          w = new byte[l / 8];

        if (!(digest instanceof sha1digest))
        {
            throw new illegalstateexception("can only use sha-1 for generating fips 186-2 parameters");
        }

        for (;;)
        {
            random.nextbytes(seed);

            hash(digest, seed, part1);
            system.arraycopy(seed, 0, part2, 0, seed.length);
            inc(part2);
            hash(digest, part2, part2);

            for (int i = 0; i != u.length; i++)
            {
                u[i] = (byte)(part1[i] ^ part2[i]);
            }

            u[0] |= (byte)0x80;
            u[19] |= (byte)0x01;

            biginteger q = new biginteger(1, u);

            if (!q.isprobableprime(certainty))
            {
                continue;
            }

            byte[] offset = arrays.clone(seed);
            inc(offset);

            for (int counter = 0; counter < 4096; ++counter)
            {
                for (int k = 0; k < n; k++)
                {
                    inc(offset);
                    hash(digest, offset, part1);
                    system.arraycopy(part1, 0, w, w.length - (k + 1) * part1.length, part1.length);
                }

                inc(offset);
                hash(digest, offset, part1);
                system.arraycopy(part1, part1.length - ((w.length - (n) * part1.length)), w, 0, w.length - n * part1.length);

                w[0] |= (byte)0x80;

                biginteger x = new biginteger(1, w);

                biginteger c = x.mod(q.shiftleft(1));

                biginteger p = x.subtract(c.subtract(one));

                if (p.bitlength() != l)
                {
                    continue;
                }

                if (p.isprobableprime(certainty))
                {
                    biginteger g = calculategenerator_fips186_2(p, q, random);

                    return new dsaparameters(p, q, g, new dsavalidationparameters(seed, counter));
                }
            }
        }
    }

    private static biginteger calculategenerator_fips186_2(biginteger p, biginteger q, securerandom r)
    {
        biginteger e = p.subtract(one).divide(q);
        biginteger psub2 = p.subtract(two);

        for (;;)
        {
            biginteger h = bigintegers.createrandominrange(two, psub2, r);
            biginteger g = h.modpow(e, p);
            if (g.bitlength() > 1)
            {
                return g;
            }
        }
    }

    /**
     * generate suitable parameters for dsa, in line with
     * <i>fips 186-3 a.1 generation of the ffc primes p and q</i>.
     */
    private dsaparameters generateparameters_fips186_3()
    {
// a.1.1.2 generation of the probable primes p and q using an approved hash function
        // fixme this should be configurable (digest size in bits must be >= n)
        digest d = digest;
        int outlen = d.getdigestsize() * 8;

// 1. check that the (l, n) pair is in the list of acceptable (l, n pairs) (see section 4.2). if
//    the pair is not in the list, then return invalid.
        // note: checked at initialisation

// 2. if (seedlen < n), then return invalid.
        // fixme this should be configurable (must be >= n)
        int seedlen = n;
        byte[] seed = new byte[seedlen / 8];

// 3. n = ceiling(l 鈦?outlen) 鈥?1.
        int n = (l - 1) / outlen;

// 4. b = l 鈥?1 鈥?(n 鈭?outlen).
        int b = (l - 1) % outlen;

        byte[] output = new byte[d.getdigestsize()];
        for (;;)
        {
// 5. get an arbitrary sequence of seedlen bits as the domain_parameter_seed.
            random.nextbytes(seed);

// 6. u = hash (domain_parameter_seed) mod 2^(n鈥?).
            hash(d, seed, output);

            biginteger u = new biginteger(1, output).mod(one.shiftleft(n - 1));

// 7. q = 2^(n鈥?) + u + 1 鈥?( u mod 2).
            biginteger q = one.shiftleft(n - 1).add(u).add(one).subtract(u.mod(two));

// 8. test whether or not q is prime as specified in appendix c.3.
            // todo review c.3 for primality checking
            if (!q.isprobableprime(certainty))
            {
// 9. if q is not a prime, then go to step 5.
                continue;
            }

// 10. offset = 1.
            // note: 'offset' value managed incrementally
            byte[] offset = arrays.clone(seed);

// 11. for counter = 0 to (4l 鈥?1) do
            int counterlimit = 4 * l;
            for (int counter = 0; counter < counterlimit; ++counter)
            {
// 11.1 for j = 0 to n do
//      vj = hash ((domain_parameter_seed + offset + j) mod 2^seedlen).
// 11.2 w = v0 + (v1 鈭?2^outlen) + ... + (v^(n鈥?) 鈭?2^((n鈥?) 鈭?outlen)) + ((vn mod 2^b) 鈭?2^(n 鈭?outlen)).
                // todo assemble w as a byte array
                biginteger w = zero;
                for (int j = 0, exp = 0; j <= n; ++j, exp += outlen)
                {
                    inc(offset);
                    hash(d, offset, output);

                    biginteger vj = new biginteger(1, output);
                    if (j == n)
                    {
                        vj = vj.mod(one.shiftleft(b));
                    }

                    w = w.add(vj.shiftleft(exp));
                }

// 11.3 x = w + 2^(l鈥?). comment: 0 鈮?w < 2l鈥?; hence, 2l鈥? 鈮?x < 2l.
                biginteger x = w.add(one.shiftleft(l - 1));
 
// 11.4 c = x mod 2q.
                biginteger c = x.mod(q.shiftleft(1));

// 11.5 p = x - (c - 1). comment: p 鈮?1 (mod 2q).
                biginteger p = x.subtract(c.subtract(one));

// 11.6 if (p < 2^(l - 1)), then go to step 11.9
                if (p.bitlength() != l)
                {
                    continue;
                }

// 11.7 test whether or not p is prime as specified in appendix c.3.
                // todo review c.3 for primality checking
                if (p.isprobableprime(certainty))
                {
// 11.8 if p is determined to be prime, then return valid and the values of p, q and
//      (optionally) the values of domain_parameter_seed and counter.
                    if (usageindex >= 0)
                    {
                        biginteger g = calculategenerator_fips186_3_verifiable(d, p, q, seed, usageindex);
                        if (g != null)
                        {
                           return new dsaparameters(p, q, g, new dsavalidationparameters(seed, counter, usageindex));
                        }
                    }

                    biginteger g = calculategenerator_fips186_3_unverifiable(p, q, random);

                    return new dsaparameters(p, q, g, new dsavalidationparameters(seed, counter));
                }

// 11.9 offset = offset + n + 1.      comment: increment offset; then, as part of
//                                    the loop in step 11, increment counter; if
//                                    counter < 4l, repeat steps 11.1 through 11.8.
                // note: 'offset' value already incremented in inner loop
            }
// 12. go to step 5.
        }
    }

    private static biginteger calculategenerator_fips186_3_unverifiable(biginteger p, biginteger q,
        securerandom r)
    {
        return calculategenerator_fips186_2(p, q, r);
    }

    private static biginteger calculategenerator_fips186_3_verifiable(digest d, biginteger p, biginteger q,
        byte[] seed, int index)
    {
// a.2.3 verifiable canonical generation of the generator g
        biginteger e = p.subtract(one).divide(q);
        byte[] ggen = hex.decode("6767656e");

        // 7. u = domain_parameter_seed || "ggen" || index || count.
        byte[] u = new byte[seed.length + ggen.length + 1 + 2];
        system.arraycopy(seed, 0, u, 0, seed.length);
        system.arraycopy(ggen, 0, u, seed.length, ggen.length);
        u[u.length - 3] = (byte)index;

        byte[] w = new byte[d.getdigestsize()];
        for (int count = 1; count < (1 << 16); ++count)
        {
            inc(u);
            hash(d, u, w);
            biginteger w = new biginteger(1, w);
            biginteger g = w.modpow(e, p);
            if (g.compareto(two) >= 0)
            {
                return g;
            }
        }

        return null;
    }

    private static void hash(digest d, byte[] input, byte[] output)
    {
        d.update(input, 0, input.length);
        d.dofinal(output, 0);
    }

    private static int getdefaultn(int l)
    {
        return l > 1024 ? 256 : 160;
    }

    private static void inc(byte[] buf)
    {
        for (int i = buf.length - 1; i >= 0; --i)
        {
            byte b = (byte)((buf[i] + 1) & 0xff);
            buf[i] = b;

            if (b != 0)
            {
                break;
            }
        }
    }
}
