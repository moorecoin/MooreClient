package org.ripple.bouncycastle.pqc.crypto.mceliece;

import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2vector;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2mfield;
import org.ripple.bouncycastle.pqc.math.linearalgebra.goppacode;
import org.ripple.bouncycastle.pqc.math.linearalgebra.permutation;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialgf2msmallm;
import org.ripple.bouncycastle.pqc.math.linearalgebra.vector;

/**
 * core operations for the cca-secure variants of mceliece.
 */
public final class mceliececca2primitives
{

    /**
     * default constructor (private).
     */
    private mceliececca2primitives()
    {
    }

    /**
     * the mceliece encryption primitive.
     *
     * @param pubkey the public key
     * @param m      the message vector
     * @param z      the error vector
     * @return <tt>m*g + z</tt>
     */


    public static gf2vector encryptionprimitive(mceliececca2publickeyparameters pubkey,
                                                gf2vector m, gf2vector z)
    {

        gf2matrix matrixg = pubkey.getmatrixg();
        vector mg = matrixg.leftmultiplyleftcompactform(m);
        return (gf2vector)mg.add(z);
    }

    /**
     * the mceliece decryption primitive.
     *
     * @param privkey the private key
     * @param c       the ciphertext vector <tt>c = m*g + z</tt>
     * @return the message vector <tt>m</tt> and the error vector <tt>z</tt>
     */
    public static gf2vector[] decryptionprimitive(
        mceliececca2privatekeyparameters privkey, gf2vector c)
    {

        // obtain values from private key
        int k = privkey.getk();
        permutation p = privkey.getp();
        gf2mfield field = privkey.getfield();
        polynomialgf2msmallm gp = privkey.getgoppapoly();
        gf2matrix h = privkey.geth();
        polynomialgf2msmallm[] q = privkey.getqinv();

        // compute inverse permutation p^-1
        permutation pinv = p.computeinverse();

        // multiply c with permutation p^-1
        gf2vector cpinv = (gf2vector)c.multiply(pinv);

        // compute syndrome of cp^-1
        gf2vector syndvec = (gf2vector)h.rightmultiply(cpinv);

        // decode syndrome
        gf2vector errors = goppacode.syndromedecode(syndvec, field, gp, q);
        gf2vector mg = (gf2vector)cpinv.add(errors);

        // multiply codeword and error vector with p
        mg = (gf2vector)mg.multiply(p);
        errors = (gf2vector)errors.multiply(p);

        // extract plaintext vector (last k columns of mg)
        gf2vector m = mg.extractrightvector(k);

        // return vectors
        return new gf2vector[]{m, errors};
    }

}
