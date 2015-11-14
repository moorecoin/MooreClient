package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;

/**
 * parameterspec for a gost 3410-94 key parameters.
 */
public class gost3410publickeyparametersetspec
{
    private biginteger p;
    private biginteger q;
    private biginteger a;
    
    /**
     * creates a new gost3410parameterspec with the specified parameter values.
     * 
     * @param p the prime.
     * @param q the sub-prime.
     * @param a the base.
     */
    public gost3410publickeyparametersetspec(
        biginteger p,
        biginteger q,
        biginteger a)
    {
        this.p = p;
        this.q = q;
        this.a = a;
    }
    
    /**
     * returns the prime <code>p</code>.
     *
     * @return the prime <code>p</code>.
     */
    public biginteger getp() 
    {
        return this.p;
    }
    
    /**
     * returns the sub-prime <code>q</code>.
     *
     * @return the sub-prime <code>q</code>.
     */
    public biginteger getq() 
    {
        return this.q;
    }
    
    /**
     * returns the base <code>a</code>.
     *
     * @return the base <code>a</code>.
     */
    public biginteger geta() 
    {
        return this.a;
    }
    
    public boolean equals(
        object o)
    {
        if (o instanceof gost3410publickeyparametersetspec)
        {
            gost3410publickeyparametersetspec other = (gost3410publickeyparametersetspec)o;
            
            return this.a.equals(other.a) && this.p.equals(other.p) && this.q.equals(other.q);
        }
        
        return false;
    }
    
    public int hashcode()
    {
        return a.hashcode() ^ p.hashcode() ^ q.hashcode();
    }
}
