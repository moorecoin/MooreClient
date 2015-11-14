package org.ripple.bouncycastle.openpgp;

/**
 * a list of pgp signatures - normally in the signature block after literal data.
 */
public class pgpsignaturelist
{
    pgpsignature[]    sigs;
    
    public pgpsignaturelist(
        pgpsignature[]    sigs)
    {
        this.sigs = new pgpsignature[sigs.length];
        
        system.arraycopy(sigs, 0, this.sigs, 0, sigs.length);
    }
    
    public pgpsignaturelist(
        pgpsignature    sig)
    {
        this.sigs = new pgpsignature[1];
        this.sigs[0] = sig;
    }
    
    public pgpsignature get(
        int    index)
    {
        return sigs[index];
    }
    
    public int size()
    {
        return sigs.length;
    }
    
    public boolean isempty()
    {
        return (sigs.length == 0);
    }
}
