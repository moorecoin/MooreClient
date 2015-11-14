package org.ripple.bouncycastle.crypto.signers;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.params.eckeyparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.math.ec.ecalgorithms;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecfieldelement;
import org.ripple.bouncycastle.math.ec.ecpoint;
import org.ripple.bouncycastle.util.arrays;

/**
 * dstu 4145-2002
 * <p>
 * national ukrainian standard of digital signature based on elliptic curves (dstu 4145-2002).
 * </p>
 */
public class dstu4145signer
    implements dsa
{
    private static final biginteger one = biginteger.valueof(1);

    private eckeyparameters key;
    private securerandom random;

    public void init(boolean forsigning, cipherparameters param)
    {
        if (forsigning)
        {
            if (param instanceof parameterswithrandom)
            {
                parameterswithrandom rparam = (parameterswithrandom)param;

                this.random = rparam.getrandom();
                param = rparam.getparameters();
            }
            else
            {
                this.random = new securerandom();
            }

            this.key = (ecprivatekeyparameters)param;
        }
        else
        {
            this.key = (ecpublickeyparameters)param;
        }

    }

    public biginteger[] generatesignature(byte[] message)
    {
        ecfieldelement h = hash2fieldelement(key.getparameters().getcurve(), message);
        if (h.tobiginteger().signum() == 0)
        {
            h = key.getparameters().getcurve().frombiginteger(one);
        }

        biginteger e, r, s;
        ecfieldelement fe, y;

        do
        {
            do
            {
                do
                {
                    e = generaterandominteger(key.getparameters().getn(), random);
                    fe = key.getparameters().getg().multiply(e).getx();
                }
                while (fe.tobiginteger().signum() == 0);

                y = h.multiply(fe);
                r = fieldelement2integer(key.getparameters().getn(), y);
            }
            while (r.signum() == 0);

            s = r.multiply(((ecprivatekeyparameters)key).getd()).add(e).mod(key.getparameters().getn());
        }
        while (s.signum() == 0);

        return new biginteger[]{r, s};
    }

    public boolean verifysignature(byte[] message, biginteger r, biginteger s)
    {
        if (r.signum() == 0 || s.signum() == 0)
        {
            return false;
        }
        if (r.compareto(key.getparameters().getn()) >= 0 || s.compareto(key.getparameters().getn()) >= 0)
        {
            return false;
        }

        ecfieldelement h = hash2fieldelement(key.getparameters().getcurve(), message);
        if (h.tobiginteger().signum() == 0)
        {
            h = key.getparameters().getcurve().frombiginteger(one);
        }

        ecpoint r = ecalgorithms.sumoftwomultiplies(key.getparameters().getg(), s, ((ecpublickeyparameters)key).getq(), r);

        // components must be bogus.
        if (r.isinfinity())
        {
            return false;
        }

        ecfieldelement y = h.multiply(r.getx());
        return fieldelement2integer(key.getparameters().getn(), y).compareto(r) == 0;
    }

    /**
     * generates random integer such, than its bit length is less than that of n
     */
    private static biginteger generaterandominteger(biginteger n, securerandom random)
    {
        return new biginteger(n.bitlength() - 1, random);
    }
    
    private static void reversebytes(byte[] bytes)
    {
        byte tmp;
        
        for (int i=0; i<bytes.length/2; i++)
        {
            tmp=bytes[i];
            bytes[i]=bytes[bytes.length-1-i];
            bytes[bytes.length-1-i]=tmp;
        }
    }

    private static ecfieldelement hash2fieldelement(eccurve curve, byte[] hash)
    {
        byte[] data = arrays.clone(hash);
        reversebytes(data);
        biginteger num = new biginteger(1, data);
        while (num.bitlength() >= curve.getfieldsize())
        {
            num = num.clearbit(num.bitlength() - 1);
        }

        return curve.frombiginteger(num);
    }

    private static biginteger fieldelement2integer(biginteger n, ecfieldelement fieldelement)
    {
        biginteger num = fieldelement.tobiginteger();
        while (num.bitlength() >= n.bitlength())
        {
            num = num.clearbit(num.bitlength() - 1);
        }

        return num;
    }
}
