package org.ripple.bouncycastle.pqc.crypto.rainbow;

import java.security.securerandom;

import org.ripple.bouncycastle.pqc.crypto.rainbow.util.gf2field;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.rainbowutil;
import org.ripple.bouncycastle.util.arrays;


/**
 * this class represents a layer of the rainbow oil- and vinegar map. each layer
 * consists of oi polynomials with their coefficients, generated at random.
 * <p/>
 * to sign a document, we solve a les (linear equation system) for each layer in
 * order to find the oil variables of that layer and to be able to use the
 * variables to compute the signature. this functionality is implemented in the
 * rainbowsignature-class, by the aid of the private key.
 * <p/>
 * each layer is a part of the private key.
 * <p/>
 * more information about the layer can be found in the paper of jintai ding,
 * dieter schmidt: rainbow, a new multivariable polynomial signature scheme.
 * acns 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
 */
public class layer
{
    private int vi; // number of vinegars in this layer
    private int vinext; // number of vinegars in next layer
    private int oi; // number of oils in this layer

    /*
      * k : index of polynomial
      *
      * i,j : indices of oil and vinegar variables
      */
    private short[/* k */][/* i */][/* j */] coeff_alpha;
    private short[/* k */][/* i */][/* j */] coeff_beta;
    private short[/* k */][/* i */] coeff_gamma;
    private short[/* k */] coeff_eta;

    /**
     * constructor
     *
     * @param vi         number of vinegar variables of this layer
     * @param vinext     number of vinegar variables of next layer. it's the same as
     *                   (num of oils) + (num of vinegars) of this layer.
     * @param coeffalpha alpha-coefficients in the polynomials of this layer
     * @param coeffbeta  beta-coefficients in the polynomials of this layer
     * @param coeffgamma gamma-coefficients in the polynomials of this layer
     * @param coeffeta   eta-coefficients in the polynomials of this layer
     */
    public layer(byte vi, byte vinext, short[][][] coeffalpha,
                 short[][][] coeffbeta, short[][] coeffgamma, short[] coeffeta)
    {
        this.vi = vi & 0xff;
        this.vinext = vinext & 0xff;
        this.oi = this.vinext - this.vi;

        // the secret coefficients of all polynomials in this layer
        this.coeff_alpha = coeffalpha;
        this.coeff_beta = coeffbeta;
        this.coeff_gamma = coeffgamma;
        this.coeff_eta = coeffeta;
    }

    /**
     * this function generates the coefficients of all polynomials in this layer
     * at random using random generator.
     *
     * @param sr the random generator which is to be used
     */
    public layer(int vi, int vinext, securerandom sr)
    {
        this.vi = vi;
        this.vinext = vinext;
        this.oi = vinext - vi;

        // the coefficients of all polynomials in this layer
        this.coeff_alpha = new short[this.oi][this.oi][this.vi];
        this.coeff_beta = new short[this.oi][this.vi][this.vi];
        this.coeff_gamma = new short[this.oi][this.vinext];
        this.coeff_eta = new short[this.oi];

        int numofpoly = this.oi; // number of polynomials per layer

        // alpha coeffs
        for (int k = 0; k < numofpoly; k++)
        {
            for (int i = 0; i < this.oi; i++)
            {
                for (int j = 0; j < this.vi; j++)
                {
                    coeff_alpha[k][i][j] = (short)(sr.nextint() & gf2field.mask);
                }
            }
        }
        // beta coeffs
        for (int k = 0; k < numofpoly; k++)
        {
            for (int i = 0; i < this.vi; i++)
            {
                for (int j = 0; j < this.vi; j++)
                {
                    coeff_beta[k][i][j] = (short)(sr.nextint() & gf2field.mask);
                }
            }
        }
        // gamma coeffs
        for (int k = 0; k < numofpoly; k++)
        {
            for (int i = 0; i < this.vinext; i++)
            {
                coeff_gamma[k][i] = (short)(sr.nextint() & gf2field.mask);
            }
        }
        // eta
        for (int k = 0; k < numofpoly; k++)
        {
            coeff_eta[k] = (short)(sr.nextint() & gf2field.mask);
        }
    }

    /**
     * this method plugs in the vinegar variables into the polynomials of this
     * layer and computes the coefficients of the oil-variables as well as the
     * free coefficient in each polynomial.
     * <p/>
     * it is needed for computing the oil variables while signing.
     *
     * @param x vinegar variables of this layer that should be plugged into
     *          the polynomials.
     * @return coeff the coefficients of oil variables and the free coeff in the
     *         polynomials of this layer.
     */
    public short[][] pluginvinegars(short[] x)
    {
        // temporary variable needed for the multiplication
        short tmpmult = 0;
        // coeff: 1st index = which polynomial, 2nd index=which variable
        short[][] coeff = new short[oi][oi + 1]; // gets returned
        // free coefficient per polynomial
        short[] sum = new short[oi];

        /*
           * evaluate the beta-part of the polynomials (it contains no oil
           * variables)
           */
        for (int k = 0; k < oi; k++)
        {
            for (int i = 0; i < vi; i++)
            {
                for (int j = 0; j < vi; j++)
                {
                    // tmp = beta * xi (plug in)
                    tmpmult = gf2field.multelem(coeff_beta[k][i][j], x[i]);
                    // tmp = tmp * xj
                    tmpmult = gf2field.multelem(tmpmult, x[j]);
                    // accumulate into the array for the free coefficients.
                    sum[k] = gf2field.addelem(sum[k], tmpmult);
                }
            }
        }

        /* evaluate the alpha-part (it contains oils) */
        for (int k = 0; k < oi; k++)
        {
            for (int i = 0; i < oi; i++)
            {
                for (int j = 0; j < vi; j++)
                {
                    // alpha * xj (plug in)
                    tmpmult = gf2field.multelem(coeff_alpha[k][i][j], x[j]);
                    // accumulate
                    coeff[k][i] = gf2field.addelem(coeff[k][i], tmpmult);
                }
            }
        }
        /* evaluate the gama-part of the polynomial (containing no oils) */
        for (int k = 0; k < oi; k++)
        {
            for (int i = 0; i < vi; i++)
            {
                // gamma * xi (plug in)
                tmpmult = gf2field.multelem(coeff_gamma[k][i], x[i]);
                // accumulate in the array for the free coefficients (per
                // polynomial).
                sum[k] = gf2field.addelem(sum[k], tmpmult);
            }
        }
        /* evaluate the gama-part of the polynomial (but containing oils) */
        for (int k = 0; k < oi; k++)
        {
            for (int i = vi; i < vinext; i++)
            { // oils
                // accumulate the coefficients of the oil variables (per
                // polynomial).
                coeff[k][i - vi] = gf2field.addelem(coeff_gamma[k][i],
                    coeff[k][i - vi]);
            }
        }
        /* evaluate the eta-part of the polynomial */
        for (int k = 0; k < oi; k++)
        {
            // accumulate in the array for the free coefficients per polynomial.
            sum[k] = gf2field.addelem(sum[k], coeff_eta[k]);
        }

        /* put the free coefficients (sum) into the coeff-array as last column */
        for (int k = 0; k < oi; k++)
        {
            coeff[k][oi] = sum[k];
        }
        return coeff;
    }

    /**
     * getter for the number of vinegar variables of this layer.
     *
     * @return the number of vinegar variables of this layer.
     */
    public int getvi()
    {
        return vi;
    }

    /**
     * getter for the number of vinegar variables of the next layer.
     *
     * @return the number of vinegar variables of the next layer.
     */
    public int getvinext()
    {
        return vinext;
    }

    /**
     * getter for the number of oil variables of this layer.
     *
     * @return the number of oil variables of this layer.
     */
    public int getoi()
    {
        return oi;
    }

    /**
     * getter for the alpha-coefficients of the polynomials in this layer.
     *
     * @return the coefficients of alpha-terms of this layer.
     */
    public short[][][] getcoeffalpha()
    {
        return coeff_alpha;
    }

    /**
     * getter for the beta-coefficients of the polynomials in this layer.
     *
     * @return the coefficients of beta-terms of this layer.
     */

    public short[][][] getcoeffbeta()
    {
        return coeff_beta;
    }

    /**
     * getter for the gamma-coefficients of the polynomials in this layer.
     *
     * @return the coefficients of gamma-terms of this layer
     */
    public short[][] getcoeffgamma()
    {
        return coeff_gamma;
    }

    /**
     * getter for the eta-coefficients of the polynomials in this layer.
     *
     * @return the coefficients eta of this layer
     */
    public short[] getcoeffeta()
    {
        return coeff_eta;
    }

    /**
     * this function compares this layer with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(object other)
    {
        if (other == null || !(other instanceof layer))
        {
            return false;
        }
        layer otherlayer = (layer)other;

        return  vi == otherlayer.getvi()
                && vinext == otherlayer.getvinext()
                && oi == otherlayer.getoi()
                && rainbowutil.equals(coeff_alpha, otherlayer.getcoeffalpha())
                && rainbowutil.equals(coeff_beta, otherlayer.getcoeffbeta())
                && rainbowutil.equals(coeff_gamma, otherlayer.getcoeffgamma())
                && rainbowutil.equals(coeff_eta, otherlayer.getcoeffeta());
    }

    public int hashcode()
    {
        int hash = vi;
        hash = hash * 37 + vinext;
        hash = hash * 37 + oi;
        hash = hash * 37 + arrays.hashcode(coeff_alpha);
        hash = hash * 37 + arrays.hashcode(coeff_beta);
        hash = hash * 37 + arrays.hashcode(coeff_gamma);
        hash = hash * 37 + arrays.hashcode(coeff_eta);

        return hash;
    }
}
