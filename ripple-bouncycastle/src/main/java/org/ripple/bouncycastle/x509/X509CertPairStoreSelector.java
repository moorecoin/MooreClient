package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.util.selector;

/**
 * this class is an <code>selector</code> like implementation to select
 * certificates pairs, which are e.g. used for cross certificates. the set of
 * criteria is given from two
 * {@link org.ripple.bouncycastle.x509.x509certstoreselector}s which must be both
 * matched.
 * 
 * @see org.ripple.bouncycastle.x509.x509attributecertificate
 * @see org.ripple.bouncycastle.x509.x509store
 */
public class x509certpairstoreselector implements selector
{

    private x509certstoreselector forwardselector;

    private x509certstoreselector reverseselector;

    private x509certificatepair certpair;

    public x509certpairstoreselector()
    {
    }

    /**
     * returns the certificate pair which is used for testing on equality.
     * 
     * @return returns the certificate pair which is checked.
     */
    public x509certificatepair getcertpair()
    {
        return certpair;
    }

    /**
     * set the certificate pair which is used for testing on equality.
     * 
     * @param certpair the certpairchecking to set.
     */
    public void setcertpair(x509certificatepair certpair)
    {
        this.certpair = certpair;
    }

    /**
     * @param forwardselector the certificate selector for the forward part in
     *            the pair.
     */
    public void setforwardselector(x509certstoreselector forwardselector)
    {
        this.forwardselector = forwardselector;
    }

    /**
     * @param reverseselector the certificate selector for the reverse part in
     *            the pair.
     */
    public void setreverseselector(x509certstoreselector reverseselector)
    {
        this.reverseselector = reverseselector;
    }

    /**
     * returns a clone of this selector.
     * 
     * @return a clone of this selector.
     * @see java.lang.object#clone()
     */
    public object clone()
    {
        x509certpairstoreselector cln = new x509certpairstoreselector();

        cln.certpair = certpair;
        
        if (forwardselector != null)
        {
            cln.setforwardselector((x509certstoreselector) forwardselector
                    .clone());
        }

        if (reverseselector != null)
        {
            cln.setreverseselector((x509certstoreselector) reverseselector
                    .clone());
        }

        return cln;
    }

    /**
     * decides if the given certificate pair should be selected. if
     * <code>obj</code> is not a {@link x509certificatepair} this method
     * returns <code>false</code>.
     * 
     * @param obj the {@link x509certificatepair} which should be tested.
     * @return <code>true</code> if the object matches this selector.
     */
    public boolean match(object obj)
    {
        try
        {
            if (!(obj instanceof x509certificatepair))
            {
                return false;
            }
            x509certificatepair pair = (x509certificatepair)obj;

            if (forwardselector != null
                    && !forwardselector.match((object)pair.getforward()))
            {
                return false;
            }

            if (reverseselector != null
                    && !reverseselector.match((object)pair.getreverse()))
            {
                return false;
            }

            if (certpair != null)
            {
                return certpair.equals(obj);
            }

            return true;
        }
        catch (exception e)
        {
            return false;
        }
    }

    /**
     * returns the certicate selector for the forward part.
     * 
     * @return returns the certicate selector for the forward part.
     */
    public x509certstoreselector getforwardselector()
    {
        return forwardselector;
    }

    /**
     * returns the certicate selector for the reverse part.
     * 
     * @return returns the reverse selector for teh reverse part.
     */
    public x509certstoreselector getreverseselector()
    {
        return reverseselector;
    }
}
