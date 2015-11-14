package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.math.bigdecimal;
import java.math.biginteger;
import java.security.securerandom;
import java.util.arraylist;
import java.util.list;
import java.util.concurrent.callable;
import java.util.concurrent.executorservice;
import java.util.concurrent.executors;
import java.util.concurrent.future;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.pqc.math.ntru.euclid.biginteuclidean;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.bigdecimalpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.bigintpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.integerpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.polynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.productformpolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.resultant;

import static java.math.biginteger.one;
import static java.math.biginteger.zero;

public class ntrusigningkeypairgenerator
    implements asymmetriccipherkeypairgenerator
{
    private ntrusigningkeygenerationparameters params;

    public void init(keygenerationparameters param)
    {
        this.params = (ntrusigningkeygenerationparameters)param;
    }

    /**
     * generates a new signature key pair. starts <code>b+1</code> threads.
     *
     * @return a key pair
     */
    public asymmetriccipherkeypair generatekeypair()
    {
        ntrusigningpublickeyparameters pub = null;
        executorservice executor = executors.newcachedthreadpool();
        list<future<ntrusigningprivatekeyparameters.basis>> bases = new arraylist<future<ntrusigningprivatekeyparameters.basis>>();
        for (int k = params.b; k >= 0; k--)
        {
            bases.add(executor.submit(new basisgenerationtask()));
        }
        executor.shutdown();

        list<ntrusigningprivatekeyparameters.basis> basises = new arraylist<ntrusigningprivatekeyparameters.basis>();

        for (int k = params.b; k >= 0; k--)
        {
            future<ntrusigningprivatekeyparameters.basis> basis = bases.get(k);
            try
            {
                basises.add(basis.get());
                if (k == params.b)
                {
                    pub = new ntrusigningpublickeyparameters(basis.get().h, params.getsigningparameters());
                }
            }
            catch (exception e)
            {
                throw new illegalstateexception(e);
            }
        }
        ntrusigningprivatekeyparameters priv = new ntrusigningprivatekeyparameters(basises, pub);
        asymmetriccipherkeypair kp = new asymmetriccipherkeypair(pub, priv);
        return kp;
    }

    /**
     * generates a new signature key pair. runs in a single thread.
     *
     * @return a key pair
     */
    public asymmetriccipherkeypair generatekeypairsinglethread()
    {
        list<ntrusigningprivatekeyparameters.basis> basises = new arraylist<ntrusigningprivatekeyparameters.basis>();
        ntrusigningpublickeyparameters pub = null;
        for (int k = params.b; k >= 0; k--)
        {
            ntrusigningprivatekeyparameters.basis basis = generateboundedbasis();
            basises.add(basis);
            if (k == 0)
            {
                pub = new ntrusigningpublickeyparameters(basis.h, params.getsigningparameters());
            }
        }
        ntrusigningprivatekeyparameters priv = new ntrusigningprivatekeyparameters(basises, pub);
        return new asymmetriccipherkeypair(pub, priv);
    }


    /**
     * implementation of the optional steps 20 through 26 in eess1v2.pdf, section 3.5.1.1.
     * this doesn't seem to have much of an effect and sometimes actually increases the
     * norm of f, but on average it slightly reduces the norm.<br/>
     * this method changes <code>f</code> and <code>g</code> but leaves <code>f</code> and
     * <code>g</code> unchanged.
     *
     * @param f
     * @param g
     * @param f
     * @param g
     * @param n
     */
    private void minimizefg(integerpolynomial f, integerpolynomial g, integerpolynomial f, integerpolynomial g, int n)
    {
        int e = 0;
        for (int j = 0; j < n; j++)
        {
            e += 2 * n * (f.coeffs[j] * f.coeffs[j] + g.coeffs[j] * g.coeffs[j]);
        }

        // [f(1)+g(1)]^2 = 4
        e -= 4;

        integerpolynomial u = (integerpolynomial)f.clone();
        integerpolynomial v = (integerpolynomial)g.clone();
        int j = 0;
        int k = 0;
        int maxadjustment = n;
        while (k < maxadjustment && j < n)
        {
            int d = 0;
            int i = 0;
            while (i < n)
            {
                int d1 = f.coeffs[i] * f.coeffs[i];
                int d2 = g.coeffs[i] * g.coeffs[i];
                int d3 = 4 * n * (d1 + d2);
                d += d3;
                i++;
            }
            // f(1)+g(1) = 2
            int d1 = 4 * (f.sumcoeffs() + g.sumcoeffs());
            d -= d1;

            if (d > e)
            {
                f.sub(u);
                g.sub(v);
                k++;
                j = 0;
            }
            else if (d < -e)
            {
                f.add(u);
                g.add(v);
                k++;
                j = 0;
            }
            j++;
            u.rotate1();
            v.rotate1();
        }
    }

    /**
     * creates a ntrusigner basis consisting of polynomials <code>f, g, f, g, h</code>.<br/>
     * if <code>keygenalg=float</code>, the basis may not be valid and this method must be rerun if that is the case.<br/>
     *
     * @see #generateboundedbasis()
     */
    private fgbasis generatebasis()
    {
        int n = params.n;
        int q = params.q;
        int d = params.d;
        int d1 = params.d1;
        int d2 = params.d2;
        int d3 = params.d3;
        int basistype = params.basistype;

        polynomial f;
        integerpolynomial fint;
        polynomial g;
        integerpolynomial gint;
        integerpolynomial fq;
        resultant rf;
        resultant rg;
        biginteuclidean r;

        int _2n1 = 2 * n + 1;
        boolean primecheck = params.primecheck;

        do
        {
            do
            {
                f = params.polytype== ntruparameters.ternary_polynomial_type_simple ? denseternarypolynomial.generaterandom(n, d + 1, d, new securerandom()) : productformpolynomial.generaterandom(n, d1, d2, d3 + 1, d3, new securerandom());
                fint = f.tointegerpolynomial();
            }
            while (primecheck && fint.resultant(_2n1).res.equals(zero));
            fq = fint.invertfq(q);
        }
        while (fq == null);
        rf = fint.resultant();

        do
        {
            do
            {
                do
                {
                    g = params.polytype == ntruparameters.ternary_polynomial_type_simple ? denseternarypolynomial.generaterandom(n, d + 1, d, new securerandom()) : productformpolynomial.generaterandom(n, d1, d2, d3 + 1, d3, new securerandom());
                    gint = g.tointegerpolynomial();
                }
                while (primecheck && gint.resultant(_2n1).res.equals(zero));
            }
            while (gint.invertfq(q) == null);
            rg = gint.resultant();
            r = biginteuclidean.calculate(rf.res, rg.res);
        }
        while (!r.gcd.equals(one));

        bigintpolynomial a = (bigintpolynomial)rf.rho.clone();
        a.mult(r.x.multiply(biginteger.valueof(q)));
        bigintpolynomial b = (bigintpolynomial)rg.rho.clone();
        b.mult(r.y.multiply(biginteger.valueof(-q)));

        bigintpolynomial c;
        if (params.keygenalg == ntrusigningkeygenerationparameters.key_gen_alg_resultant)
        {
            int[] frevcoeffs = new int[n];
            int[] grevcoeffs = new int[n];
            frevcoeffs[0] = fint.coeffs[0];
            grevcoeffs[0] = gint.coeffs[0];
            for (int i = 1; i < n; i++)
            {
                frevcoeffs[i] = fint.coeffs[n - i];
                grevcoeffs[i] = gint.coeffs[n - i];
            }
            integerpolynomial frev = new integerpolynomial(frevcoeffs);
            integerpolynomial grev = new integerpolynomial(grevcoeffs);

            integerpolynomial t = f.mult(frev);
            t.add(g.mult(grev));
            resultant rt = t.resultant();
            c = frev.mult(b);   // frev.mult(b) is actually faster than new sparseternarypolynomial(frev).mult(b), possibly due to cache locality?
            c.add(grev.mult(a));
            c = c.mult(rt.rho);
            c.div(rt.res);
        }
        else
        {   // keygenalg.float
            // calculate ceil(log10(n))
            int log10n = 0;
            for (int i = 1; i < n; i *= 10)
            {
                log10n++;
            }

            // * cdec needs to be accurate to 1 decimal place so it can be correctly rounded;
            // * finv loses up to (#digits of longest coeff of b) places in finv.mult(b);
            // * multiplying finv by b also multiplies the rounding error by a factor of n;
            // so make #decimal places of finv the sum of the above.
            bigdecimalpolynomial finv = rf.rho.div(new bigdecimal(rf.res), b.getmaxcoefflength() + 1 + log10n);
            bigdecimalpolynomial ginv = rg.rho.div(new bigdecimal(rg.res), a.getmaxcoefflength() + 1 + log10n);

            bigdecimalpolynomial cdec = finv.mult(b);
            cdec.add(ginv.mult(a));
            cdec.halve();
            c = cdec.round();
        }

        bigintpolynomial f = (bigintpolynomial)b.clone();
        f.sub(f.mult(c));
        bigintpolynomial g = (bigintpolynomial)a.clone();
        g.sub(g.mult(c));

        integerpolynomial fint = new integerpolynomial(f);
        integerpolynomial gint = new integerpolynomial(g);
        minimizefg(fint, gint, fint, gint, n);

        polynomial fprime;
        integerpolynomial h;
        if (basistype == ntrusigningkeygenerationparameters.basis_type_standard)
        {
            fprime = fint;
            h = g.mult(fq, q);
        }
        else
        {
            fprime = g;
            h = fint.mult(fq, q);
        }
        h.modpositive(q);

        return new fgbasis(f, fprime, h, fint, gint, params);
    }

    /**
     * creates a basis such that <code>|f| &lt; keynormbound</code> and <code>|g| &lt; keynormbound</code>
     *
     * @return a ntrusigner basis
     */
    public ntrusigningprivatekeyparameters.basis generateboundedbasis()
    {
        while (true)
        {
            fgbasis basis = generatebasis();
            if (basis.isnormok())
            {
                return basis;
            }
        }
    }

    private class basisgenerationtask
        implements callable<ntrusigningprivatekeyparameters.basis>
    {


        public ntrusigningprivatekeyparameters.basis call()
            throws exception
        {
            return generateboundedbasis();
        }
    }

    /**
     * a subclass of basis that additionally contains the polynomials <code>f</code> and <code>g</code>.
     */
    public class fgbasis
        extends ntrusigningprivatekeyparameters.basis
    {
        public integerpolynomial f;
        public integerpolynomial g;

        fgbasis(polynomial f, polynomial fprime, integerpolynomial h, integerpolynomial f, integerpolynomial g, ntrusigningkeygenerationparameters params)
        {
            super(f, fprime, h, params);
            this.f = f;
            this.g = g;
        }

        /**
         * returns <code>true</code> if the norms of the polynomials <code>f</code> and <code>g</code>
         * are within {@link ntrusigningkeygenerationparameters#keynormbound}.
         *
         * @return
         */
        boolean isnormok()
        {
            double keynormboundsq = params.keynormboundsq;
            int q = params.q;
            return (f.centerednormsq(q) < keynormboundsq && g.centerednormsq(q) < keynormboundsq);
        }
    }
}
