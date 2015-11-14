package org.ripple.bouncycastle.pqc.crypto.rainbow;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.crypto.messagesigner;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.computeinfield;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.gf2field;

/**
 * it implements the sign and verify functions for the rainbow signature scheme.
 * here the message, which has to be signed, is updated. the use of
 * different hash functions is possible.
 * <p/>
 * detailed information about the signature and the verify-method is to be found
 * in the paper of jintai ding, dieter schmidt: rainbow, a new multivariable
 * polynomial signature scheme. acns 2005: 164-175
 * (http://dx.doi.org/10.1007/11496137_12)
 */
public class rainbowsigner
    implements messagesigner
{
    // source of randomness
    private securerandom random;

    // the length of a document that can be signed with the privkey
    int signabledocumentlength;

    // container for the oil and vinegar variables of all the layers
    private short[] x;

    private computeinfield cf = new computeinfield();

    rainbowkeyparameters key;

    public void init(boolean forsigning,
                     cipherparameters param)
    {
        if (forsigning)
        {
            if (param instanceof parameterswithrandom)
            {
                parameterswithrandom rparam = (parameterswithrandom)param;

                this.random = rparam.getrandom();
                this.key = (rainbowprivatekeyparameters)rparam.getparameters();

            }
            else
            {

                this.random = new securerandom();
                this.key = (rainbowprivatekeyparameters)param;
            }
        }
        else
        {
            this.key = (rainbowpublickeyparameters)param;
        }

        this.signabledocumentlength = this.key.getdoclength();
    }


    /**
     * initial operations before solving the linear equation system.
     *
     * @param layer the current layer for which a les is to be solved.
     * @param msg   the message that should be signed.
     * @return y_ the modified document needed for solving les, (y_ =
     *         a1^{-1}*(y-b1)) linear map l1 = a1 x + b1.
     */
    private short[] initsign(layer[] layer, short[] msg)
    {

        /* preparation: modifies the document with the inverse of l1 */
        // tmp = y - b1:
        short[] tmpvec = new short[msg.length];

        tmpvec = cf.addvect(((rainbowprivatekeyparameters)this.key).getb1(), msg);

        // y_ = a1^{-1} * (y - b1) :
        short[] y_ = cf.multiplymatrix(((rainbowprivatekeyparameters)this.key).getinva1(), tmpvec);

        /* generates the vinegar vars of the first layer at random */
        for (int i = 0; i < layer[0].getvi(); i++)
        {
            x[i] = (short)random.nextint();
            x[i] = (short)(x[i] & gf2field.mask);
        }

        return y_;
    }

    /**
     * this function signs the message that has been updated, making use of the
     * private key.
     * <p/>
     * for computing the signature, l1 and l2 are needed, as well as les should
     * be solved for each layer in order to find the oil-variables in the layer.
     * <p/>
     * the vinegar-variables of the first layer are random generated.
     *
     * @param message the message
     * @return the signature of the message.
     */
    public byte[] generatesignature(byte[] message)
    {
        layer[] layer = ((rainbowprivatekeyparameters)this.key).getlayers();
        int numberoflayers = layer.length;

        x = new short[((rainbowprivatekeyparameters)this.key).getinva2().length]; // all variables

        short[] y_; // modified document
        short[] y_i; // part of y_ each polynomial
        int counter; // index of the current part of the doc

        short[] solvec; // the solution of les pro layer
        short[] tmpvec;

        // the signature as an array of shorts:
        short[] signature;
        // the signature as a byte-array:
        byte[] s = new byte[layer[numberoflayers - 1].getvinext()];

        short[] msghashvals = makemessagerepresentative(message);

        // shows if an exception is caught
        boolean ok;
        do
        {
            ok = true;
            counter = 0;
            try
            {
                y_ = initsign(layer, msghashvals);

                for (int i = 0; i < numberoflayers; i++)
                {

                    y_i = new short[layer[i].getoi()];
                    solvec = new short[layer[i].getoi()]; // solution of les

                    /* copy oi elements of y_ into y_i */
                    for (int k = 0; k < layer[i].getoi(); k++)
                    {
                        y_i[k] = y_[counter];
                        counter++; // current index of y_
                    }

                    /*
                          * plug in the vars of the previous layer in order to get
                          * the vars of the current layer
                          */
                    solvec = cf.solveequation(layer[i].pluginvinegars(x), y_i);

                    if (solvec == null)
                    { // les is not solveable
                        throw new exception("les is not solveable!");
                    }

                    /* copy the new vars into the x-array */
                    for (int j = 0; j < solvec.length; j++)
                    {
                        x[layer[i].getvi() + j] = solvec[j];
                    }
                }

                /* apply the inverse of l2: (signature = a2^{-1}*(b2+x)) */
                tmpvec = cf.addvect(((rainbowprivatekeyparameters)this.key).getb2(), x);
                signature = cf.multiplymatrix(((rainbowprivatekeyparameters)this.key).getinva2(), tmpvec);

                /* cast signature from short[] to byte[] */
                for (int i = 0; i < s.length; i++)
                {
                    s[i] = ((byte)signature[i]);
                }
            }
            catch (exception se)
            {
                // if one of the less was not solveable - sign again
                ok = false;
            }
        }
        while (!ok);
        /* return the signature in bytes */
        return s;
    }

    /**
     * this function verifies the signature of the message that has been
     * updated, with the aid of the public key.
     *
     * @param message the message
     * @param signature the signature of the message
     * @return true if the signature has been verified, false otherwise.
     */
    public boolean verifysignature(byte[] message, byte[] signature)
    {
        short[] sigint = new short[signature.length];
        short tmp;

        for (int i = 0; i < signature.length; i++)
        {
            tmp = (short)signature[i];
            tmp &= (short)0xff;
            sigint[i] = tmp;
        }

        short[] msghashval = makemessagerepresentative(message);

        // verify
        short[] verificationresult = verifysignatureintern(sigint);

        // compare
        boolean verified = true;
        if (msghashval.length != verificationresult.length)
        {
            return false;
        }
        for (int i = 0; i < msghashval.length; i++)
        {
            verified = verified && msghashval[i] == verificationresult[i];
        }

        return verified;
    }

    /**
     * signature verification using public key
     *
     * @param signature vector of dimension n
     * @return document hash of length n - v1
     */
    private short[] verifysignatureintern(short[] signature)
    {

        short[][] coeff_quadratic = ((rainbowpublickeyparameters)this.key).getcoeffquadratic();
        short[][] coeff_singular = ((rainbowpublickeyparameters)this.key).getcoeffsingular();
        short[] coeff_scalar = ((rainbowpublickeyparameters)this.key).getcoeffscalar();

        short[] rslt = new short[coeff_quadratic.length];// n - v1
        int n = coeff_singular[0].length;
        int offset = 0; // array position
        short tmp = 0; // for scalar

        for (int p = 0; p < coeff_quadratic.length; p++)
        { // no of polynomials
            offset = 0;
            for (int x = 0; x < n; x++)
            {
                // calculate quadratic terms
                for (int y = x; y < n; y++)
                {
                    tmp = gf2field.multelem(coeff_quadratic[p][offset],
                        gf2field.multelem(signature[x], signature[y]));
                    rslt[p] = gf2field.addelem(rslt[p], tmp);
                    offset++;
                }
                // calculate singular terms
                tmp = gf2field.multelem(coeff_singular[p][x], signature[x]);
                rslt[p] = gf2field.addelem(rslt[p], tmp);
            }
            // add scalar
            rslt[p] = gf2field.addelem(rslt[p], coeff_scalar[p]);
        }

        return rslt;
    }

    /**
     * this function creates the representative of the message which gets signed
     * or verified.
     *
     * @param message the message
     * @return message representative
     */
    private short[] makemessagerepresentative(byte[] message)
    {
        // the message representative
        short[] output = new short[this.signabledocumentlength];

        int h = 0;
        int i = 0;
        do
        {
            if (i >= message.length)
            {
                break;
            }
            output[i] = (short)message[h];
            output[i] &= (short)0xff;
            h++;
            i++;
        }
        while (i < output.length);

        return output;
    }
}
