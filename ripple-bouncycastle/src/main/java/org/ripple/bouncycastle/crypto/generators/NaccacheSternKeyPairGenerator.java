package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypairgenerator;
import org.ripple.bouncycastle.crypto.keygenerationparameters;
import org.ripple.bouncycastle.crypto.params.naccachesternkeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.naccachesternkeyparameters;
import org.ripple.bouncycastle.crypto.params.naccachesternprivatekeyparameters;

import java.math.biginteger;
import java.security.securerandom;
import java.util.vector;

/**
 * key generation parameters for naccachestern cipher. for details on this cipher, please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/ns98pkcs.pdf
 */
public class naccachesternkeypairgenerator 
    implements asymmetriccipherkeypairgenerator 
{

    private static int[] smallprimes =
    {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
        151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
        337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
        433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523,
        541, 547, 557
    };
    
    private naccachesternkeygenerationparameters param;

    private static final biginteger one = biginteger.valueof(1); // jdk 1.1 compatibility

    /*
     * (non-javadoc)
     * 
     * @see org.bouncycastle.crypto.asymmetriccipherkeypairgenerator#init(org.bouncycastle.crypto.keygenerationparameters)
     */
    public void init(keygenerationparameters param)
    {
        this.param = (naccachesternkeygenerationparameters)param;
    }

    /*
     * (non-javadoc)
     * 
     * @see org.bouncycastle.crypto.asymmetriccipherkeypairgenerator#generatekeypair()
     */
    public asymmetriccipherkeypair generatekeypair()
    {
        int strength = param.getstrength();
        securerandom rand = param.getrandom();
        int certainty = param.getcertainty();
        boolean debug = param.isdebug();

        if (debug)
        {
            system.out.println("fetching first " + param.getcntsmallprimes() + " primes.");
        }

        vector smallprimes = findfirstprimes(param.getcntsmallprimes());
        smallprimes = permutelist(smallprimes, rand);

        biginteger u = one;
        biginteger v = one;

        for (int i = 0; i < smallprimes.size() / 2; i++)
        {
            u = u.multiply((biginteger)smallprimes.elementat(i));
        }
        for (int i = smallprimes.size() / 2; i < smallprimes.size(); i++)
        {
            v = v.multiply((biginteger)smallprimes.elementat(i));
        }

        biginteger sigma = u.multiply(v);

        // n = (2 a u p_ + 1 ) ( 2 b v q_ + 1)
        // -> |n| = strength
        // |2| = 1 in bits
        // -> |a| * |b| = |n| - |u| - |v| - |p_| - |q_| - |2| -|2|
        // remainingstrength = strength - sigma.bitlength() - p_.bitlength() -
        // q_.bitlength() - 1 -1
        int remainingstrength = strength - sigma.bitlength() - 48;
        biginteger a = generateprime(remainingstrength / 2 + 1, certainty, rand);
        biginteger b = generateprime(remainingstrength / 2 + 1, certainty, rand);

        biginteger p_;
        biginteger q_;
        biginteger p;
        biginteger q;
        long tries = 0;
        if (debug)
        {
            system.out.println("generating p and q");
        }

        biginteger _2au = a.multiply(u).shiftleft(1);
        biginteger _2bv = b.multiply(v).shiftleft(1);

        for (;;)
        {
            tries++;

            p_ = generateprime(24, certainty, rand);
   
            p = p_.multiply(_2au).add(one);

            if (!p.isprobableprime(certainty))
            {
                continue;
            }

            for (;;)
            {
                q_ = generateprime(24, certainty, rand);

                if (p_.equals(q_))
                {
                    continue;
                }

                q = q_.multiply(_2bv).add(one);

                if (q.isprobableprime(certainty))
                {
                    break;
                }
            }

            if (!sigma.gcd(p_.multiply(q_)).equals(one))
            {
                // system.out.println("sigma.gcd(p_.mult(q_)) != 1!\n p_: " + p_
                // +"\n q_: "+ q_ );
                continue;
            }

            if (p.multiply(q).bitlength() < strength)
            {
                if (debug)
                {
                    system.out.println("key size too small. should be " + strength + " but is actually "
                                    + p.multiply(q).bitlength());
                }
                continue;
            }
            break;
        }

        if (debug)
        {
            system.out.println("needed " + tries + " tries to generate p and q.");
        }

        biginteger n = p.multiply(q);
        biginteger phi_n = p.subtract(one).multiply(q.subtract(one));
        biginteger g;
        tries = 0;
        if (debug)
        {
            system.out.println("generating g");
        }
        for (;;)
        {

            vector gparts = new vector();
            for (int ind = 0; ind != smallprimes.size(); ind++)
            {
                biginteger i = (biginteger)smallprimes.elementat(ind);
                biginteger e = phi_n.divide(i);

                for (;;)
                {
                    tries++;
                    g = new biginteger(strength, certainty, rand);
                    if (g.modpow(e, n).equals(one))
                    {
                        continue;
                    }
                    gparts.addelement(g);
                    break;
                }
            }
            g = one;
            for (int i = 0; i < smallprimes.size(); i++)
            {
                g = g.multiply(((biginteger)gparts.elementat(i)).modpow(sigma.divide((biginteger)smallprimes.elementat(i)), n)).mod(n);
            }

            // make sure that g is not divisible by p_i or q_i
            boolean divisible = false;
            for (int i = 0; i < smallprimes.size(); i++)
            {
                if (g.modpow(phi_n.divide((biginteger)smallprimes.elementat(i)), n).equals(one))
                {
                    if (debug)
                    {
                        system.out.println("g has order phi(n)/" + smallprimes.elementat(i) + "\n g: " + g);
                    }
                    divisible = true;
                    break;
                }
            }
            
            if (divisible)
            {
                continue;
            }

            // make sure that g has order > phi_n/4

            if (g.modpow(phi_n.divide(biginteger.valueof(4)), n).equals(one))
            {
                if (debug)
                {
                    system.out.println("g has order phi(n)/4\n g:" + g);
                }
                continue;
            }

            if (g.modpow(phi_n.divide(p_), n).equals(one))
            {
                if (debug)
                {
                    system.out.println("g has order phi(n)/p'\n g: " + g);
                }
                continue;
            }
            if (g.modpow(phi_n.divide(q_), n).equals(one))
            {
                if (debug)
                {
                    system.out.println("g has order phi(n)/q'\n g: " + g);
                }
                continue;
            }
            if (g.modpow(phi_n.divide(a), n).equals(one))
            {
                if (debug)
                {
                    system.out.println("g has order phi(n)/a\n g: " + g);
                }
                continue;
            }
            if (g.modpow(phi_n.divide(b), n).equals(one))
            {
                if (debug)
                {
                    system.out.println("g has order phi(n)/b\n g: " + g);
                }
                continue;
            }
            break;
        }
        if (debug)
        {
            system.out.println("needed " + tries + " tries to generate g");
            system.out.println();
            system.out.println("found new naccachestern cipher variables:");
            system.out.println("smallprimes: " + smallprimes);
            system.out.println("sigma:...... " + sigma + " (" + sigma.bitlength() + " bits)");
            system.out.println("a:.......... " + a);
            system.out.println("b:.......... " + b);
            system.out.println("p':......... " + p_);
            system.out.println("q':......... " + q_);
            system.out.println("p:.......... " + p);
            system.out.println("q:.......... " + q);
            system.out.println("n:.......... " + n);
            system.out.println("phi(n):..... " + phi_n);
            system.out.println("g:.......... " + g);
            system.out.println();
        }

        return new asymmetriccipherkeypair(new naccachesternkeyparameters(false, g, n, sigma.bitlength()),
                        new naccachesternprivatekeyparameters(g, n, sigma.bitlength(), smallprimes, phi_n));
    }

    private static biginteger generateprime(
            int bitlength, 
            int certainty,
            securerandom rand)
    {
        biginteger p_ = new biginteger(bitlength, certainty, rand);
        while (p_.bitlength() != bitlength)
        {
            p_ = new biginteger(bitlength, certainty, rand);
        }
        return p_;
    }

    /**
     * generates a permuted arraylist from the original one. the original list
     * is not modified
     * 
     * @param arr
     *            the arraylist to be permuted
     * @param rand
     *            the source of randomness for permutation
     * @return a new arraylist with the permuted elements.
     */
    private static vector permutelist(
        vector arr, 
        securerandom rand) 
    {
        vector retval = new vector();
        vector tmp = new vector();
        for (int i = 0; i < arr.size(); i++) 
        {
            tmp.addelement(arr.elementat(i));
        }
        retval.addelement(tmp.elementat(0));
        tmp.removeelementat(0);
        while (tmp.size() != 0) 
        {
            retval.insertelementat(tmp.elementat(0), getint(rand, retval.size() + 1));
            tmp.removeelementat(0);
        }
        return retval;
    }

    private static int getint(
        securerandom rand,
        int n)
    {
        if ((n & -n) == n) 
        {
            return (int)((n * (long)(rand.nextint() & 0x7fffffff)) >> 31);
        }

        int bits, val;
        do
        {
            bits = rand.nextint() & 0x7fffffff;
            val = bits % n;
        }
        while (bits - val + (n-1) < 0);

        return val;
    }

    /**
     * finds the first 'count' primes starting with 3
     * 
     * @param count
     *            the number of primes to find
     * @return a vector containing the found primes as integer
     */
    private static vector findfirstprimes(
        int count) 
    {
        vector primes = new vector(count);

        for (int i = 0; i != count; i++)
        {
            primes.addelement(biginteger.valueof(smallprimes[i]));
        }
        
        return primes;
    }

}
