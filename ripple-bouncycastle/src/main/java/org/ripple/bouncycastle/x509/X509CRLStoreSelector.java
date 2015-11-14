package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.x509.extension.x509extensionutil;

import java.io.ioexception;
import java.math.biginteger;
import java.security.cert.crl;
import java.security.cert.x509crl;
import java.security.cert.x509crlselector;

/**
 * this class is a selector implementation for x.509 certificate revocation
 * lists.
 * 
 * @see org.ripple.bouncycastle.util.selector
 * @see org.ripple.bouncycastle.x509.x509store
 * @see org.ripple.bouncycastle.jce.provider.x509storecrlcollection
 */
public class x509crlstoreselector
    extends x509crlselector
    implements selector
{
    private boolean deltacrlindicator = false;

    private boolean completecrlenabled = false;

    private biginteger maxbasecrlnumber = null;

    private byte[] issuingdistributionpoint = null;

    private boolean issuingdistributionpointenabled = false;

    private x509attributecertificate attrcertchecking;

    /**
     * returns if the issuing distribution point criteria should be applied.
     * defaults to <code>false</code>.
     * <p>
     * you may also set the issuing distribution point criteria if not a missing
     * issuing distribution point should be assumed.
     * 
     * @return returns if the issuing distribution point check is enabled.
     */
    public boolean isissuingdistributionpointenabled()
    {
        return issuingdistributionpointenabled;
    }

    /**
     * enables or disables the issuing distribution point check.
     * 
     * @param issuingdistributionpointenabled <code>true</code> to enable the
     *            issuing distribution point check.
     */
    public void setissuingdistributionpointenabled(
        boolean issuingdistributionpointenabled)
    {
        this.issuingdistributionpointenabled = issuingdistributionpointenabled;
    }

    /**
     * sets the attribute certificate being checked. this is not a criterion.
     * rather, it is optional information that may help a {@link x509store} find
     * crls that would be relevant when checking revocation for the specified
     * attribute certificate. if <code>null</code> is specified, then no such
     * optional information is provided.
     * 
     * @param attrcert the <code>x509attributecertificate</code> being checked (or
     *            <code>null</code>)
     * @see #getattrcertificatechecking()
     */
    public void setattrcertificatechecking(x509attributecertificate attrcert)
    {
        attrcertchecking = attrcert;
    }

    /**
     * returns the attribute certificate being checked.
     * 
     * @return returns the attribute certificate being checked.
     * @see #setattrcertificatechecking(x509attributecertificate)
     */
    public x509attributecertificate getattrcertificatechecking()
    {
        return attrcertchecking;
    }

    public boolean match(object obj)
    {
        if (!(obj instanceof x509crl))
        {
            return false;
        }
        x509crl crl = (x509crl)obj;
        derinteger dci = null;
        try
        {
            byte[] bytes = crl
                .getextensionvalue(x509extensions.deltacrlindicator.getid());
            if (bytes != null)
            {
                dci = derinteger.getinstance(x509extensionutil
                    .fromextensionvalue(bytes));
            }
        }
        catch (exception e)
        {
            return false;
        }
        if (isdeltacrlindicatorenabled())
        {
            if (dci == null)
            {
                return false;
            }
        }
        if (iscompletecrlenabled())
        {
            if (dci != null)
            {
                return false;
            }
        }
        if (dci != null)
        {

            if (maxbasecrlnumber != null)
            {
                if (dci.getpositivevalue().compareto(maxbasecrlnumber) == 1)
                {
                    return false;
                }
            }
        }
        if (issuingdistributionpointenabled)
        {
            byte[] idp = crl
                .getextensionvalue(x509extensions.issuingdistributionpoint
                    .getid());
            if (issuingdistributionpoint == null)
            {
                if (idp != null)
                {
                    return false;
                }
            }
            else
            {
                if (!arrays.areequal(idp, issuingdistributionpoint))
                {
                    return false;
                }
            }

        }
        return super.match((x509crl)obj);
    }

    public boolean match(crl crl)
    {
        return match((object)crl);
    }

    /**
     * returns if this selector must match crls with the delta crl indicator
     * extension set. defaults to <code>false</code>.
     * 
     * @return returns <code>true</code> if only crls with the delta crl
     *         indicator extension are selected.
     */
    public boolean isdeltacrlindicatorenabled()
    {
        return deltacrlindicator;
    }

    /**
     * if this is set to <code>true</code> the crl reported contains the delta
     * crl indicator crl extension.
     * <p>
     * {@link #setcompletecrlenabled(boolean)} and
     * {@link #setdeltacrlindicatorenabled(boolean)} excluded each other.
     * 
     * @param deltacrlindicator <code>true</code> if the delta crl indicator
     *            extension must be in the crl.
     */
    public void setdeltacrlindicatorenabled(boolean deltacrlindicator)
    {
        this.deltacrlindicator = deltacrlindicator;
    }

    /**
     * returns an instance of this from a <code>x509crlselector</code>.
     * 
     * @param selector a <code>x509crlselector</code> instance.
     * @return an instance of an <code>x509crlstoreselector</code>.
     * @exception illegalargumentexception if selector is null or creation
     *                fails.
     */
    public static x509crlstoreselector getinstance(x509crlselector selector)
    {
        if (selector == null)
        {
            throw new illegalargumentexception(
                "cannot create from null selector");
        }
        x509crlstoreselector cs = new x509crlstoreselector();
        cs.setcertificatechecking(selector.getcertificatechecking());
        cs.setdateandtime(selector.getdateandtime());
        try
        {
            cs.setissuernames(selector.getissuernames());
        }
        catch (ioexception e)
        {
            // cannot happen
            throw new illegalargumentexception(e.getmessage());
        }
        cs.setissuers(selector.getissuers());
        cs.setmaxcrlnumber(selector.getmaxcrl());
        cs.setmincrlnumber(selector.getmincrl());
        return cs;
    }
    
    public object clone()
    {
        x509crlstoreselector sel = x509crlstoreselector.getinstance(this);
        sel.deltacrlindicator = deltacrlindicator;
        sel.completecrlenabled = completecrlenabled;
        sel.maxbasecrlnumber = maxbasecrlnumber;
        sel.attrcertchecking = attrcertchecking;
        sel.issuingdistributionpointenabled = issuingdistributionpointenabled;
        sel.issuingdistributionpoint = arrays.clone(issuingdistributionpoint);
        return sel;
    }

    /**
     * if <code>true</code> only complete crls are returned. defaults to
     * <code>false</code>.
     * 
     * @return <code>true</code> if only complete crls are returned.
     */
    public boolean iscompletecrlenabled()
    {
        return completecrlenabled;
    }

    /**
     * if set to <code>true</code> only complete crls are returned.
     * <p>
     * {@link #setcompletecrlenabled(boolean)} and
     * {@link #setdeltacrlindicatorenabled(boolean)} excluded each other.
     * 
     * @param completecrlenabled <code>true</code> if only complete crls
     *            should be returned.
     */
    public void setcompletecrlenabled(boolean completecrlenabled)
    {
        this.completecrlenabled = completecrlenabled;
    }

    /**
     * get the maximum base crl number. defaults to <code>null</code>.
     * 
     * @return returns the maximum base crl number.
     * @see #setmaxbasecrlnumber(biginteger)
     */
    public biginteger getmaxbasecrlnumber()
    {
        return maxbasecrlnumber;
    }

    /**
     * sets the maximum base crl number. setting to <code>null</code> disables
     * this cheack.
     * <p>
     * this is only meaningful for delta crls. complete crls must have a crl
     * number which is greater or equal than the base number of the
     * corresponding crl.
     * 
     * @param maxbasecrlnumber the maximum base crl number to set.
     */
    public void setmaxbasecrlnumber(biginteger maxbasecrlnumber)
    {
        this.maxbasecrlnumber = maxbasecrlnumber;
    }

    /**
     * returns the issuing distribution point. defaults to <code>null</code>,
     * which is a missing issuing distribution point extension.
     * <p>
     * the internal byte array is cloned before it is returned.
     * <p>
     * the criteria must be enable with
     * {@link #setissuingdistributionpointenabled(boolean)}.
     * 
     * @return returns the issuing distribution point.
     * @see #setissuingdistributionpoint(byte[])
     */
    public byte[] getissuingdistributionpoint()
    {
        return arrays.clone(issuingdistributionpoint);
    }

    /**
     * sets the issuing distribution point.
     * <p>
     * the issuing distribution point extension is a crl extension which
     * identifies the scope and the distribution point of a crl. the scope
     * contains among others information about revocation reasons contained in
     * the crl. delta crls and complete crls must have matching issuing
     * distribution points.
     * <p>
     * the byte array is cloned to protect against subsequent modifications.
     * <p>
     * you must also enable or disable this criteria with
     * {@link #setissuingdistributionpointenabled(boolean)}.
     * 
     * @param issuingdistributionpoint the issuing distribution point to set.
     *            this is the der encoded octet string extension value.
     * @see #getissuingdistributionpoint()
     */
    public void setissuingdistributionpoint(byte[] issuingdistributionpoint)
    {
        this.issuingdistributionpoint = arrays.clone(issuingdistributionpoint);
    }
}
