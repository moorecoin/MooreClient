package org.ripple.bouncycastle.jce.provider;

import org.ripple.bouncycastle.asn1.x509.reasonflags;

/**
 * this class helps to handle crl revocation reasons mask. each crl handles a
 * certain set of revocation reasons.
 */
class reasonsmask
{
    private int _reasons;

    /**
     * constructs are reason mask with the reasons.
     * 
     * @param reasons the reasons.
     */
    reasonsmask(reasonflags reasons)
    {
        _reasons = reasons.intvalue();
    }

    private reasonsmask(int reasons)
    {
        _reasons = reasons;
    }

    /**
     * a reason mask with no reason.
     * 
     */
    reasonsmask()
    {
        this(0);
    }

    /**
     * a mask with all revocation reasons.
     */
    static final reasonsmask allreasons = new reasonsmask(reasonflags.aacompromise
            | reasonflags.affiliationchanged | reasonflags.cacompromise
            | reasonflags.certificatehold | reasonflags.cessationofoperation
            | reasonflags.keycompromise | reasonflags.privilegewithdrawn
            | reasonflags.unused | reasonflags.superseded);

    /**
     * adds all reasons from the reasons mask to this mask.
     * 
     * @param mask the reasons mask to add.
     */
    void addreasons(reasonsmask mask)
    {
        _reasons = _reasons | mask.getreasons();
    }

    /**
     * returns <code>true</code> if this reasons mask contains all possible
     * reasons.
     * 
     * @return <code>true</code> if this reasons mask contains all possible
     *         reasons.
     */
    boolean isallreasons()
    {
        return _reasons == allreasons._reasons ? true : false;
    }

    /**
     * intersects this mask with the given reasons mask.
     * 
     * @param mask the mask to intersect with.
     * @return the intersection of this and teh given mask.
     */
    reasonsmask intersect(reasonsmask mask)
    {
        reasonsmask _mask = new reasonsmask();
        _mask.addreasons(new reasonsmask(_reasons & mask.getreasons()));
        return _mask;
    }

    /**
     * returns <code>true</code> if the passed reasons mask has new reasons.
     * 
     * @param mask the reasons mask which should be tested for new reasons.
     * @return <code>true</code> if the passed reasons mask has new reasons.
     */
    boolean hasnewreasons(reasonsmask mask)
    {
        return ((_reasons | mask.getreasons() ^ _reasons) != 0);
    }

    /**
     * returns the reasons in this mask.
     * 
     * @return returns the reasons.
     */
    int getreasons()
    {
        return _reasons;
    }
}
