package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.util.selector;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidparameterexception;
import java.security.cert.pkixbuilderparameters;
import java.security.cert.pkixparameters;
import java.security.cert.trustanchor;
import java.security.cert.x509certselector;
import java.util.collections;
import java.util.hashset;
import java.util.set;

/**
 * this class contains extended parameters for pkix certification path builders.
 * 
 * @see java.security.cert.pkixbuilderparameters
 * @see org.ripple.bouncycastle.jce.provider.pkixcertpathbuilderspi
 */
public class extendedpkixbuilderparameters extends extendedpkixparameters
{

    private int maxpathlength = 5;

    private set excludedcerts = collections.empty_set;

    /**
     * excluded certificates are not used for building a certification path.
     * <p>
     * the returned set is immutable.
     * 
     * @return returns the excluded certificates.
     */
    public set getexcludedcerts()
    {
        return collections.unmodifiableset(excludedcerts);
    }

    /**
     * sets the excluded certificates which are not used for building a
     * certification path. if the <code>set</code> is <code>null</code> an
     * empty set is assumed.
     * <p>
     * the given set is cloned to protect it against subsequent modifications.
     * 
     * @param excludedcerts the excluded certificates to set.
     */
    public void setexcludedcerts(set excludedcerts)
    {
        if (excludedcerts == null)
        {
            excludedcerts = collections.empty_set;
        }
        else
        {
            this.excludedcerts = new hashset(excludedcerts);
        }
    }

    /**
     * creates an instance of <code>pkixbuilderparameters</code> with the
     * specified <code>set</code> of most-trusted cas. each element of the set
     * is a {@link trustanchor trustanchor}.
     * 
     * <p>
     * note that the <code>set</code> is copied to protect against subsequent
     * modifications.
     * 
     * @param trustanchors a <code>set</code> of <code>trustanchor</code>s
     * @param targetconstraints a <code>selector</code> specifying the
     *            constraints on the target certificate or attribute
     *            certificate.
     * @throws invalidalgorithmparameterexception if <code>trustanchors</code>
     *             is empty.
     * @throws nullpointerexception if <code>trustanchors</code> is
     *             <code>null</code>
     * @throws classcastexception if any of the elements of
     *             <code>trustanchors</code> is not of type
     *             <code>java.security.cert.trustanchor</code>
     */
    public extendedpkixbuilderparameters(set trustanchors,
            selector targetconstraints)
            throws invalidalgorithmparameterexception
    {
        super(trustanchors);
        settargetconstraints(targetconstraints);
    }

    /**
     * sets the maximum number of intermediate non-self-issued certificates in a
     * certification path. the pkix <code>certpathbuilder</code> must not
     * build paths longer then this length.
     * <p>
     * a value of 0 implies that the path can only contain a single certificate.
     * a value of -1 does not limit the length. the default length is 5.
     * 
     * <p>
     * 
     * the basic constraints extension of a ca certificate overrides this value
     * if smaller.
     * 
     * @param maxpathlength the maximum number of non-self-issued intermediate
     *            certificates in the certification path
     * @throws invalidparameterexception if <code>maxpathlength</code> is set
     *             to a value less than -1
     * 
     * @see org.ripple.bouncycastle.jce.provider.pkixcertpathbuilderspi
     * @see #getmaxpathlength
     */
    public void setmaxpathlength(int maxpathlength)
    {
        if (maxpathlength < -1)
        {
            throw new invalidparameterexception("the maximum path "
                    + "length parameter can not be less than -1.");
        }
        this.maxpathlength = maxpathlength;
    }

    /**
     * returns the value of the maximum number of intermediate non-self-issued
     * certificates in the certification path.
     * 
     * @return the maximum number of non-self-issued intermediate certificates
     *         in the certification path, or -1 if no limit exists.
     * 
     * @see #setmaxpathlength(int)
     */
    public int getmaxpathlength()
    {
        return maxpathlength;
    }

    /**
     * can alse handle <code>extendedpkixbuilderparameters</code> and
     * <code>pkixbuilderparameters</code>.
     * 
     * @param params parameters to set.
     * @see org.ripple.bouncycastle.x509.extendedpkixparameters#setparams(java.security.cert.pkixparameters)
     */
    protected void setparams(pkixparameters params)
    {
        super.setparams(params);
        if (params instanceof extendedpkixbuilderparameters)
        {
            extendedpkixbuilderparameters _params = (extendedpkixbuilderparameters) params;
            maxpathlength = _params.maxpathlength;
            excludedcerts = new hashset(_params.excludedcerts);
        }
        if (params instanceof pkixbuilderparameters)
        {
            pkixbuilderparameters _params = (pkixbuilderparameters) params;
            maxpathlength = _params.getmaxpathlength();
        }
    }

    /**
     * makes a copy of this <code>pkixparameters</code> object. changes to the
     * copy will not affect the original and vice versa.
     * 
     * @return a copy of this <code>pkixparameters</code> object
     */
    public object clone()
    {
        extendedpkixbuilderparameters params = null;
        try
        {
            params = new extendedpkixbuilderparameters(gettrustanchors(),
                    gettargetconstraints());
        }
        catch (exception e)
        {
            // cannot happen
            throw new runtimeexception(e.getmessage());
        }
        params.setparams(this);
        return params;
    }

    /**
     * returns an instance of <code>extendedpkixparameters</code> which can be
     * safely casted to <code>extendedpkixbuilderparameters</code>.
     * <p>
     * this method can be used to get a copy from other
     * <code>pkixbuilderparameters</code>, <code>pkixparameters</code>,
     * and <code>extendedpkixparameters</code> instances.
     * 
     * @param pkixparams the pkix parameters to create a copy of.
     * @return an <code>extendedpkixbuilderparameters</code> instance.
     */
    public static extendedpkixparameters getinstance(pkixparameters pkixparams)
    {
        extendedpkixbuilderparameters params;
        try
        {
            params = new extendedpkixbuilderparameters(pkixparams
                    .gettrustanchors(), x509certstoreselector
                    .getinstance((x509certselector) pkixparams
                            .gettargetcertconstraints()));
        }
        catch (exception e)
        {
            // cannot happen
            throw new runtimeexception(e.getmessage());
        }
        params.setparams(pkixparams);
        return params;
    }
}
