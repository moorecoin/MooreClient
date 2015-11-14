package org.ripple.bouncycastle.pqc.asn1;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.pqc.crypto.rainbow.layer;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.rainbowutil;

/**
 * return the key data to encode in the privatekeyinfo structure.
 * <p/>
 * the asn.1 definition of the key structure is
 * <p/>
 * <pre>
 *   rainbowprivatekey ::= sequence {
 *         choice
 *         {
 *         oid        object identifier         -- oid identifying the algorithm
 *         version    integer                    -- 0
 *         }
 *     a1inv      sequence of octet string  -- inversed matrix of l1
 *     b1         octet string              -- translation vector of l1
 *     a2inv      sequence of octet string  -- inversed matrix of l2
 *     b2         octet string              -- translation vector of l2
 *     vi         octet string              -- num of elmts in each set s
 *     layers     sequence of layer         -- layers of f
 *   }
 *
 *   layer             ::= sequence of poly
 *
 *   poly              ::= sequence {
 *     alpha      sequence of octet string
 *     beta       sequence of octet string
 *     gamma      octet string
 *     eta        integer
 *   }
 * </pre>
 */
public class rainbowprivatekey
    extends asn1object
{
    private asn1integer  version;
    private asn1objectidentifier oid;

    private byte[][] inva1;
    private byte[] b1;
    private byte[][] inva2;
    private byte[] b2;
    private byte[] vi;
    private layer[] layers;

    private rainbowprivatekey(asn1sequence seq)
    {
        // <oidstring>  or version
        if (seq.getobjectat(0) instanceof asn1integer)
        {
            version = asn1integer.getinstance(seq.getobjectat(0));
        }
        else
        {
            oid = asn1objectidentifier.getinstance(seq.getobjectat(0));
        }

        // <a1inv>
        asn1sequence asna1 = (asn1sequence)seq.getobjectat(1);
        inva1 = new byte[asna1.size()][];
        for (int i = 0; i < asna1.size(); i++)
        {
            inva1[i] = ((asn1octetstring)asna1.getobjectat(i)).getoctets();
        }

        // <b1>
        asn1sequence asnb1 = (asn1sequence)seq.getobjectat(2);
        b1 = ((asn1octetstring)asnb1.getobjectat(0)).getoctets();

        // <a2inv>
        asn1sequence asna2 = (asn1sequence)seq.getobjectat(3);
        inva2 = new byte[asna2.size()][];
        for (int j = 0; j < asna2.size(); j++)
        {
            inva2[j] = ((asn1octetstring)asna2.getobjectat(j)).getoctets();
        }

        // <b2>
        asn1sequence asnb2 = (asn1sequence)seq.getobjectat(4);
        b2 = ((asn1octetstring)asnb2.getobjectat(0)).getoctets();

        // <vi>
        asn1sequence asnvi = (asn1sequence)seq.getobjectat(5);
        vi = ((asn1octetstring)asnvi.getobjectat(0)).getoctets();

        // <layers>
        asn1sequence asnlayers = (asn1sequence)seq.getobjectat(6);

        byte[][][][] alphas = new byte[asnlayers.size()][][][];
        byte[][][][] betas = new byte[asnlayers.size()][][][];
        byte[][][] gammas = new byte[asnlayers.size()][][];
        byte[][] etas = new byte[asnlayers.size()][];
        // a layer:
        for (int l = 0; l < asnlayers.size(); l++)
        {
            asn1sequence asnlayer = (asn1sequence)asnlayers.getobjectat(l);

            // alphas (num of alpha-2d-array = oi)
            asn1sequence alphas3d = (asn1sequence)asnlayer.getobjectat(0);
            alphas[l] = new byte[alphas3d.size()][][];
            for (int m = 0; m < alphas3d.size(); m++)
            {
                asn1sequence alphas2d = (asn1sequence)alphas3d.getobjectat(m);
                alphas[l][m] = new byte[alphas2d.size()][];
                for (int n = 0; n < alphas2d.size(); n++)
                {
                    alphas[l][m][n] = ((asn1octetstring)alphas2d.getobjectat(n)).getoctets();
                }
            }

            // betas ....
            asn1sequence betas3d = (asn1sequence)asnlayer.getobjectat(1);
            betas[l] = new byte[betas3d.size()][][];
            for (int mb = 0; mb < betas3d.size(); mb++)
            {
                asn1sequence betas2d = (asn1sequence)betas3d.getobjectat(mb);
                betas[l][mb] = new byte[betas2d.size()][];
                for (int nb = 0; nb < betas2d.size(); nb++)
                {
                    betas[l][mb][nb] = ((asn1octetstring)betas2d.getobjectat(nb)).getoctets();
                }
            }

            // gammas ...
            asn1sequence gammas2d = (asn1sequence)asnlayer.getobjectat(2);
            gammas[l] = new byte[gammas2d.size()][];
            for (int mg = 0; mg < gammas2d.size(); mg++)
            {
                gammas[l][mg] = ((asn1octetstring)gammas2d.getobjectat(mg)).getoctets();
            }

            // eta ...
            etas[l] = ((asn1octetstring)asnlayer.getobjectat(3)).getoctets();
        }

        int numoflayers = vi.length - 1;
        this.layers = new layer[numoflayers];
        for (int i = 0; i < numoflayers; i++)
        {
            layer l = new layer(vi[i], vi[i + 1], rainbowutil.convertarray(alphas[i]),
                rainbowutil.convertarray(betas[i]), rainbowutil.convertarray(gammas[i]), rainbowutil.convertarray(etas[i]));
            this.layers[i] = l;

        }
    }

    public rainbowprivatekey(short[][] inva1, short[] b1, short[][] inva2,
                                   short[] b2, int[] vi, layer[] layers)
    {
        this.version = new asn1integer(1);
        this.inva1 = rainbowutil.convertarray(inva1);
        this.b1 = rainbowutil.convertarray(b1);
        this.inva2 = rainbowutil.convertarray(inva2);
        this.b2 = rainbowutil.convertarray(b2);
        this.vi = rainbowutil.convertintarray(vi);
        this.layers = layers;
    }
    
    public static rainbowprivatekey getinstance(object o)
    {
        if (o instanceof rainbowprivatekey)
        {
            return (rainbowprivatekey)o;
        }
        else if (o != null)
        {
            return new rainbowprivatekey(asn1sequence.getinstance(o));
        }

        return null;
    }

    public asn1integer getversion()
    {
        return version;
    }

    /**
     * getter for the inverse matrix of a1.
     *
     * @return the a1inv inverse
     */
    public short[][] getinva1()
    {
        return rainbowutil.convertarray(inva1);
    }

    /**
     * getter for the translation part of the private quadratic map l1.
     *
     * @return b1 the translation part of l1
     */
    public short[] getb1()
    {
        return rainbowutil.convertarray(b1);
    }

    /**
     * getter for the translation part of the private quadratic map l2.
     *
     * @return b2 the translation part of l2
     */
    public short[] getb2()
    {
        return rainbowutil.convertarray(b2);
    }

    /**
     * getter for the inverse matrix of a2
     *
     * @return the a2inv
     */
    public short[][] getinva2()
    {
        return rainbowutil.convertarray(inva2);
    }

    /**
     * returns the layers contained in the private key
     *
     * @return layers
     */
    public layer[] getlayers()
    {
        return this.layers;
    }

    /**
     * returns the array of vi-s
     *
     * @return the vi
     */
    public int[] getvi()
    {
        return rainbowutil.convertarraytoint(vi);
    }
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        // encode <oidstring>  or version
        if (version != null)
        {
            v.add(version);
        }
        else
        {
            v.add(oid);
        }

        // encode <a1inv>
        asn1encodablevector asna1 = new asn1encodablevector();
        for (int i = 0; i < inva1.length; i++)
        {
            asna1.add(new deroctetstring(inva1[i]));
        }
        v.add(new dersequence(asna1));

        // encode <b1>
        asn1encodablevector asnb1 = new asn1encodablevector();
        asnb1.add(new deroctetstring(b1));
        v.add(new dersequence(asnb1));

        // encode <a2inv>
        asn1encodablevector asna2 = new asn1encodablevector();
        for (int i = 0; i < inva2.length; i++)
        {
            asna2.add(new deroctetstring(inva2[i]));
        }
        v.add(new dersequence(asna2));

        // encode <b2>
        asn1encodablevector asnb2 = new asn1encodablevector();
        asnb2.add(new deroctetstring(b2));
        v.add(new dersequence(asnb2));

        // encode <vi>
        asn1encodablevector asnvi = new asn1encodablevector();
        asnvi.add(new deroctetstring(vi));
        v.add(new dersequence(asnvi));

        // encode <layers>
        asn1encodablevector asnlayers = new asn1encodablevector();
        // a layer:
        for (int l = 0; l < layers.length; l++)
        {
            asn1encodablevector alayer = new asn1encodablevector();

            // alphas (num of alpha-2d-array = oi)
            byte[][][] alphas = rainbowutil.convertarray(layers[l].getcoeffalpha());
            asn1encodablevector alphas3d = new asn1encodablevector();
            for (int i = 0; i < alphas.length; i++)
            {
                asn1encodablevector alphas2d = new asn1encodablevector();
                for (int j = 0; j < alphas[i].length; j++)
                {
                    alphas2d.add(new deroctetstring(alphas[i][j]));
                }
                alphas3d.add(new dersequence(alphas2d));
            }
            alayer.add(new dersequence(alphas3d));

            // betas ....
            byte[][][] betas = rainbowutil.convertarray(layers[l].getcoeffbeta());
            asn1encodablevector betas3d = new asn1encodablevector();
            for (int i = 0; i < betas.length; i++)
            {
                asn1encodablevector betas2d = new asn1encodablevector();
                for (int j = 0; j < betas[i].length; j++)
                {
                    betas2d.add(new deroctetstring(betas[i][j]));
                }
                betas3d.add(new dersequence(betas2d));
            }
            alayer.add(new dersequence(betas3d));

            // gammas ...
            byte[][] gammas = rainbowutil.convertarray(layers[l].getcoeffgamma());
            asn1encodablevector asng = new asn1encodablevector();
            for (int i = 0; i < gammas.length; i++)
            {
                asng.add(new deroctetstring(gammas[i]));
            }
            alayer.add(new dersequence(asng));

            // eta
            alayer.add(new deroctetstring(rainbowutil.convertarray(layers[l].getcoeffeta())));

            // now, layer built up. add it!
            asnlayers.add(new dersequence(alayer));
        }

        v.add(new dersequence(asnlayers));

        return new dersequence(v);
    }
}
