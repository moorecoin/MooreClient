package org.ripple.bouncycastle.asn1.ua;

import java.math.biginteger;
import java.util.random;

import org.ripple.bouncycastle.asn1.x9.x9integerconverter;
import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecfieldelement;
import org.ripple.bouncycastle.math.ec.ecpoint;
import org.ripple.bouncycastle.util.arrays;

/**
 * dstu4145 encodes points somewhat differently than x9.62
 * it compresses the point to the size of the field element
 */

public abstract class dstu4145pointencoder
{

    private static x9integerconverter converter = new x9integerconverter();

    private static biginteger trace(ecfieldelement fe)
    {
        ecfieldelement t = fe;
        for (int i = 0; i < fe.getfieldsize() - 1; i++)
        {
            t = t.square().add(fe);
        }
        return t.tobiginteger();
    }

    /**
     * solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(x9.62
     * d.1.6) the other solution is <code>z + 1</code>.
     *
     * @param beta the value to solve the qradratic equation for.
     * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
     *         <code>null</code> if no solution exists.
     */
    private static ecfieldelement solvequadradicequation(ecfieldelement beta)
    {
        ecfieldelement.f2m b = (ecfieldelement.f2m)beta;
        ecfieldelement zeroelement = new ecfieldelement.f2m(
            b.getm(), b.getk1(), b.getk2(), b.getk3(), ecconstants.zero);

        if (beta.tobiginteger().equals(ecconstants.zero))
        {
            return zeroelement;
        }

        ecfieldelement z = null;
        ecfieldelement gamma = zeroelement;

        random rand = new random();
        int m = b.getm();
        do
        {
            ecfieldelement t = new ecfieldelement.f2m(b.getm(), b.getk1(),
                b.getk2(), b.getk3(), new biginteger(m, rand));
            z = zeroelement;
            ecfieldelement w = beta;
            for (int i = 1; i <= m - 1; i++)
            {
                ecfieldelement w2 = w.square();
                z = z.square().add(w2.multiply(t));
                w = w2.add(beta);
            }
            if (!w.tobiginteger().equals(ecconstants.zero))
            {
                return null;
            }
            gamma = z.square().add(z);
        }
        while (gamma.tobiginteger().equals(ecconstants.zero));

        return z;
    }

    public static byte[] encodepoint(ecpoint q)
    {
        /*if (!q.iscompressed())
              q=new ecpoint.f2m(q.getcurve(),q.getx(),q.gety(),true);

          byte[] bytes=q.getencoded();

          if (bytes[0]==0x02)
              bytes[bytes.length-1]&=0xfe;
          else if (bytes[0]==0x02)
              bytes[bytes.length-1]|=0x01;

          return arrays.copyofrange(bytes, 1, bytes.length);*/

        int bytecount = converter.getbytelength(q.getx());
        byte[] bytes = converter.integertobytes(q.getx().tobiginteger(), bytecount);

        if (!(q.getx().tobiginteger().equals(ecconstants.zero)))
        {
            ecfieldelement y = q.gety().multiply(q.getx().invert());
            if (trace(y).equals(ecconstants.one))
            {
                bytes[bytes.length - 1] |= 0x01;
            }
            else
            {
                bytes[bytes.length - 1] &= 0xfe;
            }
        }

        return bytes;
    }

    public static ecpoint decodepoint(eccurve curve, byte[] bytes)
    {
        /*byte[] bp_enc=new byte[bytes.length+1];
          if (0==(bytes[bytes.length-1]&0x1))
              bp_enc[0]=0x02;
          else
              bp_enc[0]=0x03;
          system.arraycopy(bytes, 0, bp_enc, 1, bytes.length);
          if (!trace(curve.frombiginteger(new biginteger(1, bytes))).equals(curve.geta().tobiginteger()))
              bp_enc[bp_enc.length-1]^=0x01;

          return curve.decodepoint(bp_enc);*/

        biginteger k = biginteger.valueof(bytes[bytes.length - 1] & 0x1);
        if (!trace(curve.frombiginteger(new biginteger(1, bytes))).equals(curve.geta().tobiginteger()))
        {
            bytes = arrays.clone(bytes);
            bytes[bytes.length - 1] ^= 0x01;
        }
        eccurve.f2m c = (eccurve.f2m)curve;
        ecfieldelement xp = curve.frombiginteger(new biginteger(1, bytes));
        ecfieldelement yp = null;
        if (xp.tobiginteger().equals(ecconstants.zero))
        {
            yp = (ecfieldelement.f2m)curve.getb();
            for (int i = 0; i < c.getm() - 1; i++)
            {
                yp = yp.square();
            }
        }
        else
        {
            ecfieldelement beta = xp.add(curve.geta()).add(
                curve.getb().multiply(xp.square().invert()));
            ecfieldelement z = solvequadradicequation(beta);
            if (z == null)
            {
                throw new runtimeexception("invalid point compression");
            }
            if (!trace(z).equals(k))
            {
                z = z.add(curve.frombiginteger(ecconstants.one));
            }
            yp = xp.multiply(z);
        }

        return new ecpoint.f2m(curve, xp, yp);
    }

}
