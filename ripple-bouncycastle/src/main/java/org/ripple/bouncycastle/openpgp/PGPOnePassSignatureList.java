package org.ripple.bouncycastle.openpgp;

/**
 * holder for a list of pgponepasssignatures
 */
public class pgponepasssignaturelist
{
    pgponepasssignature[]    sigs;
    
    public pgponepasssignaturelist(
        pgponepasssignature[]    sigs)
    {
        this.sigs = new pgponepasssignature[sigs.length];
        
        system.arraycopy(sigs, 0, this.sigs, 0, sigs.length);
    }
    
    public pgponepasssignaturelist(
        pgponepasssignature    sig)
    {
        this.sigs = new pgponepasssignature[1];
        this.sigs[0] = sig;
    }
    
    public pgponepasssignature get(
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
