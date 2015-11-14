package org.ripple.bouncycastle.crypto.agreement.srp;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.util.bigintegers;

public class srp6util
{
    private static biginteger zero = biginteger.valueof(0);
    private static biginteger one = biginteger.valueof(1);

    public static biginteger calculatek(digest digest, biginteger n, biginteger g)
    {
        return hashpaddedpair(digest, n, n, g);
    }

    public static biginteger calculateu(digest digest, biginteger n, biginteger a, biginteger b)
    {
        return hashpaddedpair(digest, n, a, b);
    }

    public static biginteger calculatex(digest digest, biginteger n, byte[] salt, byte[] identity, byte[] password)
    {
        byte[] output = new byte[digest.getdigestsize()];

        digest.update(identity, 0, identity.length);
        digest.update((byte)':');
        digest.update(password, 0, password.length);
        digest.dofinal(output, 0);

        digest.update(salt, 0, salt.length);
        digest.update(output, 0, output.length);
        digest.dofinal(output, 0);

        return new biginteger(1, output);
    }

    public static biginteger generateprivatevalue(digest digest, biginteger n, biginteger g, securerandom random)
    {
        int minbits = math.min(256, n.bitlength() / 2);
        biginteger min = one.shiftleft(minbits - 1);
        biginteger max = n.subtract(one);

        return bigintegers.createrandominrange(min, max, random);
    }

    public static biginteger validatepublicvalue(biginteger n, biginteger val)
        throws cryptoexception
    {
        val = val.mod(n);

        // check that val % n != 0
        if (val.equals(zero))
        {
            throw new cryptoexception("invalid public value: 0");
        }

        return val;
    }

    private static biginteger hashpaddedpair(digest digest, biginteger n, biginteger n1, biginteger n2)
    {
        int padlength = (n.bitlength() + 7) / 8;

        byte[] n1_bytes = getpadded(n1, padlength);
        byte[] n2_bytes = getpadded(n2, padlength);

        digest.update(n1_bytes, 0, n1_bytes.length);
        digest.update(n2_bytes, 0, n2_bytes.length);

        byte[] output = new byte[digest.getdigestsize()];
        digest.dofinal(output, 0);

        return new biginteger(1, output);
    }

    private static byte[] getpadded(biginteger n, int length)
    {
        byte[] bs = bigintegers.asunsignedbytearray(n);
        if (bs.length < length)
        {
            byte[] tmp = new byte[length];
            system.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
            bs = tmp;
        }
        return bs;
    }
}
