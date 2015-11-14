package org.ripple.bouncycastle.pqc.crypto.ntru;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.integerpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.polynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.productformpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.util.util;

/**
 * generates key pairs.<br/>
 * the parameter p is hardcoded to 3.
 */
public class ntruencryptionkeypairgenerator
    implements asymmetriccipherkeypairgenerator
{
    private ntruencryptionkeygenerationparameters params;

    /**
     * constructs a new instance with a set of encryption parameters.
     *
     * @param param encryption parameters
     */
    public void init(keygenerationparameters param)
    {
        this.params = (ntruencryptionkeygenerationparameters)param;
    }

    /**
     * generates a new encryption key pair.
     *
     * @return a key pair
     */
    public asymmetriccipherkeypair generatekeypair()
    {
        int n = params.n;
        int q = params.q;
        int df = params.df;
        int df1 = params.df1;
        int df2 = params.df2;
        int df3 = params.df3;
        int dg = params.dg;
        boolean fastfp = params.fastfp;
        boolean sparse = params.sparse;

        polynomial t;
        integerpolynomial fq;
        integerpolynomial fp = null;

        // choose a random f that is invertible mod 3 and q
        while (true)
        {
            integerpolynomial f;

            // choose random t, calculate f and fp
            if (fastfp)
            {
                // if fastfp=true, f is always invertible mod 3
                t = params.polytype == ntruparameters.ternary_polynomial_type_simple ? util.generaterandomternary(n, df, df, sparse, params.getrandom()) : productformpolynomial.generaterandom(n, df1, df2, df3, df3, params.getrandom());
                f = t.tointegerpolynomial();
                f.mult(3);
                f.coeffs[0] += 1;
            }
            else
            {
                t = params.polytype == ntruparameters.ternary_polynomial_type_simple ? util.generaterandomternary(n, df, df - 1, sparse, params.getrandom()) : productformpolynomial.generaterandom(n, df1, df2, df3, df3 - 1, params.getrandom());
                f = t.tointegerpolynomial();
                fp = f.invertf3();
                if (fp == null)
                {
                    continue;
                }
            }

            fq = f.invertfq(q);
            if (fq == null)
            {
                continue;
            }
            break;
        }

        // if fastfp=true, fp=1
        if (fastfp)
        {
            fp = new integerpolynomial(n);
            fp.coeffs[0] = 1;
        }

        // choose a random g that is invertible mod q
        denseternarypolynomial g;
        while (true)
        {
            g = denseternarypolynomial.generaterandom(n, dg, dg - 1, params.getrandom());
            if (g.invertfq(q) != null)
            {
                break;
            }
        }

        integerpolynomial h = g.mult(fq, q);
        h.mult3(q);
        h.ensurepositive(q);
        g.clear();
        fq.clear();

        ntruencryptionprivatekeyparameters priv = new ntruencryptionprivatekeyparameters(h, t, fp, params.getencryptionparameters());
        ntruencryptionpublickeyparameters pub = new ntruencryptionpublickeyparameters(h, params.getencryptionparameters());
        return new asymmetriccipherkeypair(pub, priv);
    }
}