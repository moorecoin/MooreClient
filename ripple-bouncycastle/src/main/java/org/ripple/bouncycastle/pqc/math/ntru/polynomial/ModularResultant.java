package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import java.math.biginteger;

import org.ripple.bouncycastle.pqc.math.ntru.euclid.biginteuclidean;

/**
 * a resultant modulo a <code>biginteger</code>
 */
public class modularresultant
    extends resultant
{
    biginteger modulus;

    modularresultant(bigintpolynomial rho, biginteger res, biginteger modulus)
    {
        super(rho, res);
        this.modulus = modulus;
    }

    /**
     * calculates a <code>rho</code> modulo <code>m1*m2</code> from
     * two resultants whose <code>rho</code>s are modulo <code>m1</code> and <code>m2</code>.<br/>
     * </code>res</code> is set to <code>null</code>.
     *
     * @param modres1
     * @param modres2
     * @return <code>rho</code> modulo <code>modres1.modulus * modres2.modulus</code>, and <code>null</code> for </code>res</code>.
     */
    static modularresultant combinerho(modularresultant modres1, modularresultant modres2)
    {
        biginteger mod1 = modres1.modulus;
        biginteger mod2 = modres2.modulus;
        biginteger prod = mod1.multiply(mod2);
        biginteuclidean er = biginteuclidean.calculate(mod2, mod1);

        bigintpolynomial rho1 = (bigintpolynomial)modres1.rho.clone();
        rho1.mult(er.x.multiply(mod2));
        bigintpolynomial rho2 = (bigintpolynomial)modres2.rho.clone();
        rho2.mult(er.y.multiply(mod1));
        rho1.add(rho2);
        rho1.mod(prod);

        return new modularresultant(rho1, null, prod);
    }
}
