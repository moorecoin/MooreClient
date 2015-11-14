package org.ripple.bouncycastle.pqc.crypto.mceliece;


import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2mfield;
import org.ripple.bouncycastle.pqc.math.linearalgebra.goppacode;
import org.ripple.bouncycastle.pqc.math.linearalgebra.permutation;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialgf2msmallm;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialringgf2m;
import org.ripple.bouncycastle.pqc.math.linearalgebra.goppacode.mamape;


/**
 * this class implements key pair generation of the mceliece public key
 * cryptosystem (mceliecepkc).
 */
public class mceliececca2keypairgenerator
    implements asymmetriccipherkeypairgenerator
{


    /**
     * the oid of the algorithm.
     */
    public static final string oid = "1.3.6.1.4.1.8301.3.1.3.4.2";

    private mceliececca2keygenerationparameters mceliececca2params;

    // the extension degree of the finite field gf(2^m)
    private int m;

    // the length of the code
    private int n;

    // the error correction capability
    private int t;

    // the field polynomial
    private int fieldpoly;

    // the source of randomness
    private securerandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized = false;

    /**
     * default initialization of the key pair generator.
     */
    private void initializedefault()
    {
        mceliececca2keygenerationparameters mccca2params = new mceliececca2keygenerationparameters(new securerandom(), new mceliececca2parameters());
        init(mccca2params);
    }

    // todo
    public void init(
        keygenerationparameters param)
    {
        this.mceliececca2params = (mceliececca2keygenerationparameters)param;

        // set source of randomness
        this.random = new securerandom();

        this.m = this.mceliececca2params.getparameters().getm();
        this.n = this.mceliececca2params.getparameters().getn();
        this.t = this.mceliececca2params.getparameters().gett();
        this.fieldpoly = this.mceliececca2params.getparameters().getfieldpoly();
        this.initialized = true;
    }


    public asymmetriccipherkeypair generatekeypair()
    {

        if (!initialized)
        {
            initializedefault();
        }

        // finite field gf(2^m)
        gf2mfield field = new gf2mfield(m, fieldpoly);

        // irreducible goppa polynomial
        polynomialgf2msmallm gp = new polynomialgf2msmallm(field, t,
            polynomialgf2msmallm.random_irreducible_polynomial, random);
        polynomialringgf2m ring = new polynomialringgf2m(field, gp);

        // matrix for computing square roots in (gf(2^m))^t
        polynomialgf2msmallm[] qinv = ring.getsquarerootmatrix();

        // generate canonical check matrix
        gf2matrix h = goppacode.createcanonicalcheckmatrix(field, gp);

        // compute short systematic form of check matrix
        mamape mmp = goppacode.computesystematicform(h, random);
        gf2matrix shorth = mmp.getsecondmatrix();
        permutation p = mmp.getpermutation();

        // compute short systematic form of generator matrix
        gf2matrix shortg = (gf2matrix)shorth.computetranspose();

        // obtain number of rows of g (= dimension of the code)
        int k = shortg.getnumrows();

        // generate keys
        mceliececca2publickeyparameters pubkey = new mceliececca2publickeyparameters(oid, n, t, shortg, mceliececca2params.getparameters());
        mceliececca2privatekeyparameters privkey = new mceliececca2privatekeyparameters(oid, n, k,
            field, gp, p, h, qinv, mceliececca2params.getparameters());

        // return key pair
        return new asymmetriccipherkeypair(pubkey, privkey);
    }
}
