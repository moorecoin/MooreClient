package org.ripple.bouncycastle.jce;

import java.security.spec.ecfieldf2m;
import java.security.spec.ecfieldfp;
import java.security.spec.ecpoint;
import java.security.spec.ellipticcurve;

import org.ripple.bouncycastle.math.ec.eccurve;

/**
 * utility class for handling ec point decoding.
 */
public class ecpointutil
{
    /**
     * decode a point on this curve which has been encoded using point
     * compression (x9.62 s 4.2.1 and 4.2.2) or regular encoding.
     * 
     * @param curve
     *            the elliptic curve.
     * @param encoded
     *            the encoded point.
     * @return the decoded point.
     */
    public static ecpoint decodepoint(
       ellipticcurve curve, 
       byte[] encoded)
    {
        eccurve c = null;
        
        if (curve.getfield() instanceof ecfieldfp)
        {
            c = new eccurve.fp(
                    ((ecfieldfp)curve.getfield()).getp(), curve.geta(), curve.getb());
        }
        else
        {
            int k[] = ((ecfieldf2m)curve.getfield()).getmidtermsofreductionpolynomial();
            
            if (k.length == 3)
            {
                c = new eccurve.f2m(
                        ((ecfieldf2m)curve.getfield()).getm(), k[2], k[1], k[0], curve.geta(), curve.getb());
            }
            else
            {
                c = new eccurve.f2m(
                        ((ecfieldf2m)curve.getfield()).getm(), k[0], curve.geta(), curve.getb());
            }
        }
        
        org.ripple.bouncycastle.math.ec.ecpoint p = c.decodepoint(encoded);
        
        return new ecpoint(p.getx().tobiginteger(), p.gety().tobiginteger());
    }
}
