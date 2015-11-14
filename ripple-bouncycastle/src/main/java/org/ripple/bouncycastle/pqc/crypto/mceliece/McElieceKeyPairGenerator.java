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
public class mceliecekeypairgenerator
    implements asymmetriccipherkeypairgenerator
{


    public mceliecekeypairgenerator()
    {

    }


    /**
     * the oid of the algorithm.
     */
    private static final string oid = "1.3.6.1.4.1.8301.3.1.3.4.1";

    private mceliecekeygenerationparameters mcelieceparams;

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
        mceliecekeygenerationparameters mcparams = new mceliecekeygenerationparameters(new securerandom(), new mcelieceparameters());
        initialize(mcparams);
    }

    private void initialize(
        keygenerationparameters param)
    {
        this.mcelieceparams = (mceliecekeygenerationparameters)param;

        // set source of randomness
        this.random = new securerandom();

        this.m = this.mcelieceparams.getparameters().getm();
        this.n = this.mcelieceparams.getparameters().getn();
        this.t = this.mcelieceparams.getparameters().gett();
        this.fieldpoly = this.mcelieceparams.getparameters().getfieldpoly();
        this.initialized = true;
    }


    private asymmetriccipherkeypair genkeypair()
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

        // matrix used to compute square roots in (gf(2^m))^t
        polynomialgf2msmallm[] sqrootmatrix = ring.getsquarerootmatrix();

        // generate canonical check matrix
        gf2matrix h = goppacode.createcanonicalcheckmatrix(field, gp);

        // compute short systematic form of check matrix
        mamape mmp = goppacode.computesystematicform(h, random);
        gf2matrix shorth = mmp.getsecondmatrix();
        permutation p1 = mmp.getpermutation();

        // compute short systematic form of generator matrix
        gf2matrix shortg = (gf2matrix)shorth.computetranspose();

        // extend to full systematic form
        gf2matrix gprime = shortg.extendleftcompactform();

        // obtain number of rows of g (= dimension of the code)
        int k = shortg.getnumrows();

        // generate random invertible (k x k)-matrix s and its inverse s^-1
        gf2matrix[] matrixsandinverse = gf2matrix
            .createrandomregularmatrixanditsinverse(k, random);

        // generate random permutation p2
        permutation p2 = new permutation(n, random);

        // compute public matrix g=s*g'*p2
        gf2matrix g = (gf2matrix)matrixsandinverse[0].rightmultiply(gprime);
        g = (gf2matrix)g.rightmultiply(p2);


        // generate keys
        mceliecepublickeyparameters pubkey = new mceliecepublickeyparameters(oid, n, t, g, mcelieceparams.getparameters());
        mcelieceprivatekeyparameters privkey = new mcelieceprivatekeyparameters(oid, n, k,
            field, gp, matrixsandinverse[1], p1, p2, h, sqrootmatrix, mcelieceparams.getparameters());

        // return key pair
        return new asymmetriccipherkeypair(pubkey, privkey);
    }

    public void init(keygenerationparameters param)
    {
        this.initialize(param);

    }

    public asymmetriccipherkeypair generatekeypair()
    {
        return genkeypair();
    }

}
