package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.params.gost3410parameters;
import org.ripple.bouncycastle.crypto.params.gost3410validationparameters;

import java.math.biginteger;
import java.security.securerandom;

/**
 * generate suitable parameters for gost3410.
 */
public class gost3410parametersgenerator
{
    private int             size;
    private int             typeproc;
    private securerandom    init_random;

    private static final biginteger one = biginteger.valueof(1);
    private static final biginteger two = biginteger.valueof(2);

    /**
     * initialise the key generator.
     *
     * @param size size of the key
     * @param typeproc type procedure a,b = 1;  a',b' - else
     * @param random random byte source.
     */
    public void init(
        int             size,
        int             typeproc,
        securerandom    random)
    {
        this.size = size;
        this.typeproc = typeproc;
        this.init_random = random;
    }

    //procedure a
    private int procedure_a(int x0, int c,  biginteger[] pq, int size)
    {
        //verify and perform condition: 0<x<2^16; 0<c<2^16; c - odd.
        while(x0<0 || x0>65536)
        {
            x0 = init_random.nextint()/32768;
        }

        while((c<0 || c>65536) || (c/2==0))
        {
            c = init_random.nextint()/32768 + 1;
        }

        biginteger c = new biginteger(integer.tostring(c));
        biginteger consta16 = new biginteger("19381");

        //step1
        biginteger[] y = new biginteger[1]; // begin length = 1
        y[0] = new biginteger(integer.tostring(x0));

        //step 2
        int[] t = new int[1]; // t - orders; begin length = 1
        t[0] = size;
        int s = 0;
        for (int i=0; t[i]>=17; i++)
        {
            // extension array t
            int tmp_t[] = new int[t.length + 1];             ///////////////
            system.arraycopy(t,0,tmp_t,0,t.length);          //  extension
            t = new int[tmp_t.length];                       //  array t
            system.arraycopy(tmp_t, 0, t, 0, tmp_t.length);  ///////////////

            t[i+1] = t[i]/2;
            s = i+1;
        }

        //step3
        biginteger p[] = new biginteger[s+1];
        p[s] = new biginteger("8003",16); //set min prime number length 16 bit

        int m = s-1;  //step4

        for (int i=0; i<s; i++)
        {
            int rm = t[m]/16;  //step5

     step6: for(;;)
            {
                //step 6
                biginteger tmp_y[] = new biginteger[y.length];  ////////////////
                system.arraycopy(y,0,tmp_y,0,y.length);         //  extension
                y = new biginteger[rm+1];                       //  array y
                system.arraycopy(tmp_y,0,y,0,tmp_y.length);     ////////////////

                for (int j=0; j<rm; j++)
                {
                    y[j+1] = (y[j].multiply(consta16).add(c)).mod(two.pow(16));
                }

                //step 7
                biginteger ym = new biginteger("0");
                for (int j=0; j<rm; j++)
                {
                    ym = ym.add(y[j].multiply(two.pow(16*j)));
                }

                y[0] = y[rm]; //step 8

                //step 9
                biginteger n = two.pow(t[m]-1).divide(p[m+1]).
                                   add((two.pow(t[m]-1).multiply(ym)).
                                       divide(p[m+1].multiply(two.pow(16*rm))));

                if (n.mod(two).compareto(one)==0) 
                {
                    n = n.add(one);
                }

                int k = 0; //step 10

        step11: for(;;)
                {
                    //step 11
                    p[m] = p[m+1].multiply(n.add(biginteger.valueof(k))).add(one);

                    if (p[m].compareto(two.pow(t[m]))==1)
                    {
                        continue step6; //step 12
                    }

                    //step13
                    if ((two.modpow(p[m+1].multiply(n.add(biginteger.valueof(k))),p[m]).compareto(one)==0) &&
                        (two.modpow(n.add(biginteger.valueof(k)),p[m]).compareto(one)!=0))
                    {
                        m -= 1;
                        break;
                    }
                    else
                    {
                        k += 2;
                        continue step11;
                    }
                }

                if (m>=0) 
                {
                    break; //step 14
                }
                else
                {
                    pq[0] = p[0];
                    pq[1] = p[1];
                    return y[0].intvalue(); //return for procedure b step 2
                }
            }
        }
        return y[0].intvalue();
    }

    //procedure a'
    private long procedure_aa(long x0, long c, biginteger[] pq, int size)
    {
        //verify and perform condition: 0<x<2^32; 0<c<2^32; c - odd.
        while(x0<0 || x0>4294967296l)
        {
            x0 = init_random.nextint()*2;
        }

        while((c<0 || c>4294967296l) || (c/2==0))
        {
            c = init_random.nextint()*2+1;
        }

        biginteger c = new biginteger(long.tostring(c));
        biginteger consta32 = new biginteger("97781173");

        //step1
        biginteger[] y = new biginteger[1]; // begin length = 1
        y[0] = new biginteger(long.tostring(x0));

        //step 2
        int[] t = new int[1]; // t - orders; begin length = 1
        t[0] = size;
        int s = 0;
        for (int i=0; t[i]>=33; i++)
        {
            // extension array t
            int tmp_t[] = new int[t.length + 1];             ///////////////
            system.arraycopy(t,0,tmp_t,0,t.length);          //  extension
            t = new int[tmp_t.length];                       //  array t
            system.arraycopy(tmp_t, 0, t, 0, tmp_t.length);  ///////////////

            t[i+1] = t[i]/2;
            s = i+1;
        }

        //step3
        biginteger p[] = new biginteger[s+1];
        p[s] = new biginteger("8000000b",16); //set min prime number length 32 bit

        int m = s-1;  //step4

        for (int i=0; i<s; i++)
        {
            int rm = t[m]/32;  //step5

     step6: for(;;)
            {
                //step 6
                biginteger tmp_y[] = new biginteger[y.length];  ////////////////
                system.arraycopy(y,0,tmp_y,0,y.length);         //  extension
                y = new biginteger[rm+1];                       //  array y
                system.arraycopy(tmp_y,0,y,0,tmp_y.length);     ////////////////

                for (int j=0; j<rm; j++)
                {
                    y[j+1] = (y[j].multiply(consta32).add(c)).mod(two.pow(32));
                }

                //step 7
                biginteger ym = new biginteger("0");
                for (int j=0; j<rm; j++)
                {
                    ym = ym.add(y[j].multiply(two.pow(32*j)));
                }

                y[0] = y[rm]; //step 8

                //step 9
                biginteger n = two.pow(t[m]-1).divide(p[m+1]).
                                   add((two.pow(t[m]-1).multiply(ym)).
                                       divide(p[m+1].multiply(two.pow(32*rm))));

                if (n.mod(two).compareto(one)==0) 
                {
                    n = n.add(one);
                }

                int k = 0; //step 10

        step11: for(;;)
                {
                    //step 11
                    p[m] = p[m+1].multiply(n.add(biginteger.valueof(k))).add(one);

                    if (p[m].compareto(two.pow(t[m]))==1)
                    {
                        continue step6; //step 12
                    }

                    //step13
                    if ((two.modpow(p[m+1].multiply(n.add(biginteger.valueof(k))),p[m]).compareto(one)==0) &&
                        (two.modpow(n.add(biginteger.valueof(k)),p[m]).compareto(one)!=0))
                    {
                        m -= 1;
                        break;
                    }
                    else
                    {
                        k += 2;
                        continue step11;
                    }
                }

                if (m>=0)
                {
                    break; //step 14
                }
                else
                {
                    pq[0] = p[0];
                    pq[1] = p[1];
                    return y[0].longvalue(); //return for procedure b' step 2
                }
            }
        }
        return y[0].longvalue();
    }

    //procedure b
    private void procedure_b(int x0, int c, biginteger[] pq)
    {
        //verify and perform condition: 0<x<2^16; 0<c<2^16; c - odd.
        while(x0<0 || x0>65536)
        {
            x0 = init_random.nextint()/32768;
        }

        while((c<0 || c>65536) || (c/2==0))
        {
            c = init_random.nextint()/32768 + 1;
        }

        biginteger [] qp = new biginteger[2];
        biginteger q = null, q = null, p = null;
        biginteger c = new biginteger(integer.tostring(c));
        biginteger consta16 = new biginteger("19381");

        //step1
        x0 = procedure_a(x0, c, qp, 256);
        q = qp[0];

        //step2
        x0 = procedure_a(x0, c, qp, 512);
        q = qp[0];

        biginteger[] y = new biginteger[65];
        y[0] = new biginteger(integer.tostring(x0));

        int tp = 1024;

 step3: for(;;)
        {
            //step 3
            for (int j=0; j<64; j++)
            {
                y[j+1] = (y[j].multiply(consta16).add(c)).mod(two.pow(16));
            }

            //step 4
            biginteger y = new biginteger("0");
 
            for (int j=0; j<64; j++)
            {
                y = y.add(y[j].multiply(two.pow(16*j)));
            }

            y[0] = y[64]; //step 5

            //step 6
            biginteger n = two.pow(tp-1).divide(q.multiply(q)).
                               add((two.pow(tp-1).multiply(y)).
                                   divide(q.multiply(q).multiply(two.pow(1024))));

            if (n.mod(two).compareto(one)==0)
            {
                n = n.add(one);
            }

            int k = 0; //step 7

     step8: for(;;)
            {
                //step 11
                p = q.multiply(q).multiply(n.add(biginteger.valueof(k))).add(one);

                if (p.compareto(two.pow(tp))==1)
                {
                    continue step3; //step 9
                }

                //step10
                if ((two.modpow(q.multiply(q).multiply(n.add(biginteger.valueof(k))),p).compareto(one)==0) &&
                    (two.modpow(q.multiply(n.add(biginteger.valueof(k))),p).compareto(one)!=0))
                {
                    pq[0] = p;
                    pq[1] = q;
                    return;
                }
                else
                {
                    k += 2;
                    continue step8;
                }
            }
        }
    }

    //procedure b'
    private void procedure_bb(long x0, long c, biginteger[] pq)
    {
        //verify and perform condition: 0<x<2^32; 0<c<2^32; c - odd.
        while(x0<0 || x0>4294967296l)
        {
            x0 = init_random.nextint()*2;
        }

        while((c<0 || c>4294967296l) || (c/2==0))
        {
            c = init_random.nextint()*2+1;
        }

        biginteger [] qp = new biginteger[2];
        biginteger q = null, q = null, p = null;
        biginteger c = new biginteger(long.tostring(c));
        biginteger consta32 = new biginteger("97781173");

        //step1
        x0 = procedure_aa(x0, c, qp, 256);
        q = qp[0];

        //step2
        x0 = procedure_aa(x0, c, qp, 512);
        q = qp[0];

        biginteger[] y = new biginteger[33];
        y[0] = new biginteger(long.tostring(x0));

        int tp = 1024;

 step3: for(;;)
        {
            //step 3
            for (int j=0; j<32; j++)
            {
                y[j+1] = (y[j].multiply(consta32).add(c)).mod(two.pow(32));
            }

            //step 4
            biginteger y = new biginteger("0");
            for (int j=0; j<32; j++)
            {
                y = y.add(y[j].multiply(two.pow(32*j)));
            }

            y[0] = y[32]; //step 5

            //step 6
            biginteger n = two.pow(tp-1).divide(q.multiply(q)).
                               add((two.pow(tp-1).multiply(y)).
                                   divide(q.multiply(q).multiply(two.pow(1024))));

            if (n.mod(two).compareto(one)==0)
            {
                n = n.add(one);
            }

            int k = 0; //step 7

     step8: for(;;)
            {
                //step 11
                p = q.multiply(q).multiply(n.add(biginteger.valueof(k))).add(one);

                if (p.compareto(two.pow(tp))==1)
                {
                    continue step3; //step 9
                }

                //step10
                if ((two.modpow(q.multiply(q).multiply(n.add(biginteger.valueof(k))),p).compareto(one)==0) &&
                    (two.modpow(q.multiply(n.add(biginteger.valueof(k))),p).compareto(one)!=0))
                {
                    pq[0] = p;
                    pq[1] = q;
                    return;
                }
                else
                {
                    k += 2;
                    continue step8;
                }
            }
        }
    }


    /**
     * procedure c
     * procedure generates the a value from the given p,q,
     * returning the a value.
     */
    private biginteger procedure_c(biginteger p, biginteger q)
    {
        biginteger psub1 = p.subtract(one);
        biginteger psub1divq = psub1.divide(q);
        int length = p.bitlength();

        for(;;)
        {
            biginteger d = new biginteger(length, init_random);

            // 1 < d < p-1
            if (d.compareto(one) > 0 && d.compareto(psub1) < 0)
            {
                biginteger a = d.modpow(psub1divq, p);

                if (a.compareto(one) != 0)
                {
                    return a;
                }
            }
        }
    }

    /**
     * which generates the p , q and a values from the given parameters,
     * returning the gost3410parameters object.
     */
    public gost3410parameters generateparameters()
    {
        biginteger [] pq = new biginteger[2];
        biginteger    q = null, p = null, a = null;

        int  x0, c;
        long  x0l, cl;

        if (typeproc==1)
        {
            x0 = init_random.nextint();
            c  = init_random.nextint();

            switch(size)
            {
            case 512:  
                procedure_a(x0, c, pq, 512); 
                break;
            case 1024: 
                procedure_b(x0, c, pq); 
                break;
            default: 
                throw new illegalargumentexception("ooops! key size 512 or 1024 bit.");
            }
            p = pq[0];  q = pq[1];
            a = procedure_c(p, q);
            //system.out.println("p:"+p.tostring(16)+"\n"+"q:"+q.tostring(16)+"\n"+"a:"+a.tostring(16));
            //system.out.println("p:"+p+"\n"+"q:"+q+"\n"+"a:"+a);
            return new gost3410parameters(p, q, a, new gost3410validationparameters(x0, c));
        }
        else
        {
            x0l = init_random.nextlong();
            cl  = init_random.nextlong();

            switch(size)
            {
            case 512:  
                procedure_aa(x0l, cl, pq, 512); 
                break;
            case 1024: 
                procedure_bb(x0l, cl, pq); 
                break;
            default: 
                throw new illegalstateexception("ooops! key size 512 or 1024 bit.");
            }
            p = pq[0];  q = pq[1];
            a = procedure_c(p, q);
            //system.out.println("p:"+p.tostring(16)+"\n"+"q:"+q.tostring(16)+"\n"+"a:"+a.tostring(16));
            //system.out.println("p:"+p+"\n"+"q:"+q+"\n"+"a:"+a);
            return new gost3410parameters(p, q, a, new gost3410validationparameters(x0l, cl));
        }
    }
}
