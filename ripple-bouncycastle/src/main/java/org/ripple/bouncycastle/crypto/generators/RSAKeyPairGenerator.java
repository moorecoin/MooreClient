package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.rsakeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;

import java.math.biginteger;

/**
 * an rsa key pair generator.
 */
public class rsakeypairgenerator
    implements asymmetriccipherkeypairgenerator
{
    private static final biginteger one = biginteger.valueof(1);

    private rsakeygenerationparameters param;

    public void init(
        keygenerationparameters param)
    {
        this.param = (rsakeygenerationparameters)param;
    }

    public asymmetriccipherkeypair generatekeypair()
    {
        biginteger    p, q, n, d, e, psub1, qsub1, phi;

        //
        // p and q values should have a length of half the strength in bits
        //
        int strength = param.getstrength();
        int pbitlength = (strength + 1) / 2;
        int qbitlength = strength - pbitlength;
        int mindiffbits = strength / 3;

        e = param.getpublicexponent();

        // todo consider generating safe primes for p, q (see dhparametershelper.generatesafeprimes)
        // (then p-1 and q-1 will not consist of only small factors - see "pollard's algorithm")

        //
        // generate p, prime and (p-1) relatively prime to e
        //
        for (;;)
        {
            p = new biginteger(pbitlength, 1, param.getrandom());
            
            if (p.mod(e).equals(one))
            {
                continue;
            }
            
            if (!p.isprobableprime(param.getcertainty()))
            {
                continue;
            }
            
            if (e.gcd(p.subtract(one)).equals(one)) 
            {
                break;
            }
        }

        //
        // generate a modulus of the required length
        //
        for (;;)
        {
            // generate q, prime and (q-1) relatively prime to e,
            // and not equal to p
            //
            for (;;)
            {
                q = new biginteger(qbitlength, 1, param.getrandom());

                if (q.subtract(p).abs().bitlength() < mindiffbits)
                {
                    continue;
                }
                
                if (q.mod(e).equals(one))
                {
                    continue;
                }
            
                if (!q.isprobableprime(param.getcertainty()))
                {
                    continue;
                }
            
                if (e.gcd(q.subtract(one)).equals(one)) 
                {
                    break;
                } 
            }

            //
            // calculate the modulus
            //
            n = p.multiply(q);

            if (n.bitlength() == param.getstrength()) 
            {
                break;
            } 

            //
            // if we get here our primes aren't big enough, make the largest
            // of the two p and try again
            //
            p = p.max(q);
        }

        if (p.compareto(q) < 0)
        {
            phi = p;
            p = q;
            q = phi;
        }

        psub1 = p.subtract(one);
        qsub1 = q.subtract(one);
        phi = psub1.multiply(qsub1);

        //
        // calculate the private exponent
        //
        d = e.modinverse(phi);

        //
        // calculate the crt factors
        //
        biginteger    dp, dq, qinv;

        dp = d.remainder(psub1);
        dq = d.remainder(qsub1);
        qinv = q.modinverse(p);

        return new asymmetriccipherkeypair(
                new rsakeyparameters(false, n, e),
                new rsaprivatecrtkeyparameters(n, e, d, p, q, dp, dq, qinv));
    }
}
