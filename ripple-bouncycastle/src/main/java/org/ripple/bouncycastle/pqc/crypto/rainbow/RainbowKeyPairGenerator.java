package org.ripple.bouncycastle.pqc.crypto.rainbow;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.computeinfield;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.gf2field;

/**
 * this class implements asymmetriccipherkeypairgenerator. it is used
 * as a generator for the private and public key of the rainbow signature
 * scheme.
 * <p/>
 * detailed information about the key generation is to be found in the paper of
 * jintai ding, dieter schmidt: rainbow, a new multivariable polynomial
 * signature scheme. acns 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
 */
public class rainbowkeypairgenerator
    implements asymmetriccipherkeypairgenerator
{
    private boolean initialized = false;
    private securerandom sr;
    private rainbowkeygenerationparameters rainbowparams;

    /* linear affine map l1: */
    private short[][] a1; // matrix of the lin. affine map l1(n-v1 x n-v1 matrix)
    private short[][] a1inv; // inverted a1
    private short[] b1; // translation element of the lin.affine map l1

    /* linear affine map l2: */
    private short[][] a2; // matrix of the lin. affine map (n x n matrix)
    private short[][] a2inv; // inverted a2
    private short[] b2; // translation elemt of the lin.affine map l2

    /* components of f: */
    private int numoflayers; // u (number of sets s)
    private layer layers[]; // layers of polynomials of f
    private int[] vi; // set of vinegar vars per layer.

    /* components of public key */
    private short[][] pub_quadratic; // quadratic(mixed) coefficients
    private short[][] pub_singular; // singular coefficients
    private short[] pub_scalar; // scalars

    // todo

    /**
     * the standard constructor tries to generate the rainbow algorithm identifier
     * with the corresponding oid.
     * <p/>
     */
    public rainbowkeypairgenerator()
    {
    }


    /**
     * this function generates a rainbow key pair.
     *
     * @return the generated key pair
     */
    public asymmetriccipherkeypair genkeypair()
    {
        rainbowprivatekeyparameters privkey;
        rainbowpublickeyparameters pubkey;

        if (!initialized)
        {
            initializedefault();
        }

        /* choose all coefficients at random */
        keygen();

        /* now marshall them to privatekey */
        privkey = new rainbowprivatekeyparameters(a1inv, b1, a2inv, b2, vi, layers);


        /* marshall to publickey */
        pubkey = new rainbowpublickeyparameters(vi[vi.length - 1] - vi[0], pub_quadratic, pub_singular, pub_scalar);

        return new asymmetriccipherkeypair(pubkey, privkey);
    }

    // todo
    public void initialize(
        keygenerationparameters param)
    {
        this.rainbowparams = (rainbowkeygenerationparameters)param;

        // set source of randomness
        this.sr = new securerandom();

        // unmarshalling:
        this.vi = this.rainbowparams.getparameters().getvi();
        this.numoflayers = this.rainbowparams.getparameters().getnumoflayers();

        this.initialized = true;
    }

    private void initializedefault()
    {
        rainbowkeygenerationparameters rbkgparams = new rainbowkeygenerationparameters(new securerandom(), new rainbowparameters());
        initialize(rbkgparams);
    }

    /**
     * this function calls the functions for the random generation of the coefficients
     * and the matrices needed for the private key and the method for computing the public key.
     */
    private void keygen()
    {
        generatel1();
        generatel2();
        generatef();
        computepublickey();
    }

    /**
     * this function generates the invertible affine linear map l1 = a1*x + b1
     * <p/>
     * the translation part b1, is stored in a separate array. the inverse of
     * the matrix-part of l1 a1inv is also computed here.
     * <p/>
     * this linear map hides the output of the map f. it is on k^(n-v1).
     */
    private void generatel1()
    {

        // dimension = n-v1 = vi[last] - vi[first]
        int dim = vi[vi.length - 1] - vi[0];
        this.a1 = new short[dim][dim];
        this.a1inv = null;
        computeinfield c = new computeinfield();

        /* generation of a1 at random */
        while (a1inv == null)
        {
            for (int i = 0; i < dim; i++)
            {
                for (int j = 0; j < dim; j++)
                {
                    a1[i][j] = (short)(sr.nextint() & gf2field.mask);
                }
            }
            a1inv = c.inverse(a1);
        }

        /* generation of the translation vector at random */
        b1 = new short[dim];
        for (int i = 0; i < dim; i++)
        {
            b1[i] = (short)(sr.nextint() & gf2field.mask);
        }
    }

    /**
     * this function generates the invertible affine linear map l2 = a2*x + b2
     * <p/>
     * the translation part b2, is stored in a separate array. the inverse of
     * the matrix-part of l2 a2inv is also computed here.
     * <p/>
     * this linear map hides the output of the map f. it is on k^(n).
     */
    private void generatel2()
    {

        // dimension = n = vi[last]
        int dim = vi[vi.length - 1];
        this.a2 = new short[dim][dim];
        this.a2inv = null;
        computeinfield c = new computeinfield();

        /* generation of a2 at random */
        while (this.a2inv == null)
        {
            for (int i = 0; i < dim; i++)
            {
                for (int j = 0; j < dim; j++)
                { // one col extra for b
                    a2[i][j] = (short)(sr.nextint() & gf2field.mask);
                }
            }
            this.a2inv = c.inverse(a2);
        }
        /* generation of the translation vector at random */
        b2 = new short[dim];
        for (int i = 0; i < dim; i++)
        {
            b2[i] = (short)(sr.nextint() & gf2field.mask);
        }

    }

    /**
     * this function generates the private map f, which consists of u-1 layers.
     * each layer consists of oi polynomials where oi = vi[i+1]-vi[i].
     * <p/>
     * the methods for the generation of the coefficients of these polynomials
     * are called here.
     */
    private void generatef()
    {

        this.layers = new layer[this.numoflayers];
        for (int i = 0; i < this.numoflayers; i++)
        {
            layers[i] = new layer(this.vi[i], this.vi[i + 1], sr);
        }
    }

    /**
     * this function computes the public key from the private key.
     * <p/>
     * the composition of f with l2 is computed, followed by applying l1 to the
     * composition's result. the singular and scalar values constitute to the
     * public key as is, the quadratic terms are compacted in
     * <tt>compactpublickey()</tt>
     */
    private void computepublickey()
    {

        computeinfield c = new computeinfield();
        int rows = this.vi[this.vi.length - 1] - this.vi[0];
        int vars = this.vi[this.vi.length - 1];
        // fpub
        short[][][] coeff_quadratic_3dim = new short[rows][vars][vars];
        this.pub_singular = new short[rows][vars];
        this.pub_scalar = new short[rows];

        // coefficients of layers of private key f
        short[][][] coeff_alpha;
        short[][][] coeff_beta;
        short[][] coeff_gamma;
        short[] coeff_eta;

        // needed for counters;
        int oils = 0;
        int vins = 0;
        int crnt_row = 0; // current row (polynomial)

        short vect_tmp[] = new short[vars]; // vector tmp;
        short sclr_tmp = 0;

        // composition of f and l2: insert l2 = a2*x+b2 in f
        for (int l = 0; l < this.layers.length; l++)
        {
            // get coefficients of current layer
            coeff_alpha = this.layers[l].getcoeffalpha();
            coeff_beta = this.layers[l].getcoeffbeta();
            coeff_gamma = this.layers[l].getcoeffgamma();
            coeff_eta = this.layers[l].getcoeffeta();
            oils = coeff_alpha[0].length;// this.layers[l].getoi();
            vins = coeff_beta[0].length;// this.layers[l].getvi();
            // compute polynomials of layer
            for (int p = 0; p < oils; p++)
            {
                // multiply alphas
                for (int x1 = 0; x1 < oils; x1++)
                {
                    for (int x2 = 0; x2 < vins; x2++)
                    {
                        // multiply polynomial1 with polynomial2
                        vect_tmp = c.multvect(coeff_alpha[p][x1][x2],
                            this.a2[x1 + vins]);
                        coeff_quadratic_3dim[crnt_row + p] = c.addsquarematrix(
                            coeff_quadratic_3dim[crnt_row + p], c
                            .multvects(vect_tmp, this.a2[x2]));
                        // mul poly1 with scalar2
                        vect_tmp = c.multvect(this.b2[x2], vect_tmp);
                        this.pub_singular[crnt_row + p] = c.addvect(vect_tmp,
                            this.pub_singular[crnt_row + p]);
                        // mul scalar1 with poly2
                        vect_tmp = c.multvect(coeff_alpha[p][x1][x2],
                            this.a2[x2]);
                        vect_tmp = c.multvect(b2[x1 + vins], vect_tmp);
                        this.pub_singular[crnt_row + p] = c.addvect(vect_tmp,
                            this.pub_singular[crnt_row + p]);
                        // mul scalar1 with scalar2
                        sclr_tmp = gf2field.multelem(coeff_alpha[p][x1][x2],
                            this.b2[x1 + vins]);
                        this.pub_scalar[crnt_row + p] = gf2field.addelem(
                            this.pub_scalar[crnt_row + p], gf2field
                            .multelem(sclr_tmp, this.b2[x2]));
                    }
                }
                // multiply betas
                for (int x1 = 0; x1 < vins; x1++)
                {
                    for (int x2 = 0; x2 < vins; x2++)
                    {
                        // multiply polynomial1 with polynomial2
                        vect_tmp = c.multvect(coeff_beta[p][x1][x2],
                            this.a2[x1]);
                        coeff_quadratic_3dim[crnt_row + p] = c.addsquarematrix(
                            coeff_quadratic_3dim[crnt_row + p], c
                            .multvects(vect_tmp, this.a2[x2]));
                        // mul poly1 with scalar2
                        vect_tmp = c.multvect(this.b2[x2], vect_tmp);
                        this.pub_singular[crnt_row + p] = c.addvect(vect_tmp,
                            this.pub_singular[crnt_row + p]);
                        // mul scalar1 with poly2
                        vect_tmp = c.multvect(coeff_beta[p][x1][x2],
                            this.a2[x2]);
                        vect_tmp = c.multvect(this.b2[x1], vect_tmp);
                        this.pub_singular[crnt_row + p] = c.addvect(vect_tmp,
                            this.pub_singular[crnt_row + p]);
                        // mul scalar1 with scalar2
                        sclr_tmp = gf2field.multelem(coeff_beta[p][x1][x2],
                            this.b2[x1]);
                        this.pub_scalar[crnt_row + p] = gf2field.addelem(
                            this.pub_scalar[crnt_row + p], gf2field
                            .multelem(sclr_tmp, this.b2[x2]));
                    }
                }
                // multiply gammas
                for (int n = 0; n < vins + oils; n++)
                {
                    // mul poly with scalar
                    vect_tmp = c.multvect(coeff_gamma[p][n], this.a2[n]);
                    this.pub_singular[crnt_row + p] = c.addvect(vect_tmp,
                        this.pub_singular[crnt_row + p]);
                    // mul scalar with scalar
                    this.pub_scalar[crnt_row + p] = gf2field.addelem(
                        this.pub_scalar[crnt_row + p], gf2field.multelem(
                        coeff_gamma[p][n], this.b2[n]));
                }
                // add eta
                this.pub_scalar[crnt_row + p] = gf2field.addelem(
                    this.pub_scalar[crnt_row + p], coeff_eta[p]);
            }
            crnt_row = crnt_row + oils;
        }

        // apply l1 = a1*x+b1 to composition of f and l2
        {
            // temporary coefficient arrays
            short[][][] tmp_c_quad = new short[rows][vars][vars];
            short[][] tmp_c_sing = new short[rows][vars];
            short[] tmp_c_scal = new short[rows];
            for (int r = 0; r < rows; r++)
            {
                for (int q = 0; q < a1.length; q++)
                {
                    tmp_c_quad[r] = c.addsquarematrix(tmp_c_quad[r], c
                        .multmatrix(a1[r][q], coeff_quadratic_3dim[q]));
                    tmp_c_sing[r] = c.addvect(tmp_c_sing[r], c.multvect(
                        a1[r][q], this.pub_singular[q]));
                    tmp_c_scal[r] = gf2field.addelem(tmp_c_scal[r], gf2field
                        .multelem(a1[r][q], this.pub_scalar[q]));
                }
                tmp_c_scal[r] = gf2field.addelem(tmp_c_scal[r], b1[r]);
            }
            // set public key
            coeff_quadratic_3dim = tmp_c_quad;
            this.pub_singular = tmp_c_sing;
            this.pub_scalar = tmp_c_scal;
        }
        compactpublickey(coeff_quadratic_3dim);
    }

    /**
     * the quadratic (or mixed) terms of the public key are compacted from a n x
     * n matrix per polynomial to an upper diagonal matrix stored in one integer
     * array of n (n + 1) / 2 elements per polynomial. the ordering of elements
     * is lexicographic and the result is updating <tt>this.pub_quadratic</tt>,
     * which stores the quadratic elements of the public key.
     *
     * @param coeff_quadratic_to_compact 3-dimensional array containing a n x n matrix for each of the
     *                                   n - v1 polynomials
     */
    private void compactpublickey(short[][][] coeff_quadratic_to_compact)
    {
        int polynomials = coeff_quadratic_to_compact.length;
        int n = coeff_quadratic_to_compact[0].length;
        int entries = n * (n + 1) / 2;// the small gauss
        this.pub_quadratic = new short[polynomials][entries];
        int offset = 0;

        for (int p = 0; p < polynomials; p++)
        {
            offset = 0;
            for (int x = 0; x < n; x++)
            {
                for (int y = x; y < n; y++)
                {
                    if (y == x)
                    {
                        this.pub_quadratic[p][offset] = coeff_quadratic_to_compact[p][x][y];
                    }
                    else
                    {
                        this.pub_quadratic[p][offset] = gf2field.addelem(
                            coeff_quadratic_to_compact[p][x][y],
                            coeff_quadratic_to_compact[p][y][x]);
                    }
                    offset++;
                }
            }
        }
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
