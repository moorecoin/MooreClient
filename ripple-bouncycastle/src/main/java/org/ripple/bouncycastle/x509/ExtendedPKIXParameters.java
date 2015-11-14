package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.util.store;

import java.security.invalidalgorithmparameterexception;
import java.security.cert.certselector;
import java.security.cert.certstore;
import java.security.cert.pkixparameters;
import java.security.cert.trustanchor;
import java.security.cert.x509certselector;
import java.util.arraylist;
import java.util.collections;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.set;

/**
 * this class extends the pkixparameters with a validity model parameter.
 */
public class extendedpkixparameters
    extends pkixparameters
{

    private list stores;

    private selector selector;

    private boolean additionallocationsenabled;

    private list additionalstores;

    private set trustedacissuers;

    private set necessaryacattributes;

    private set prohibitedacattributes;

    private set attrcertcheckers;

    /**
     * creates an instance of <code>pkixparameters</code> with the specified
     * <code>set</code> of most-trusted cas. each element of the set is a
     * {@link trustanchor trustanchor}. <p/> note that the <code>set</code>
     * is copied to protect against subsequent modifications.
     * 
     * @param trustanchors a <code>set</code> of <code>trustanchor</code>s
     * @throws invalidalgorithmparameterexception if the specified
     *             <code>set</code> is empty.
     * @throws nullpointerexception if the specified <code>set</code> is
     *             <code>null</code>
     * @throws classcastexception if any of the elements in the <code>set</code>
     *             is not of type <code>java.security.cert.trustanchor</code>
     */
    public extendedpkixparameters(set trustanchors)
        throws invalidalgorithmparameterexception
    {
        super(trustanchors);
        stores = new arraylist();
        additionalstores = new arraylist();
        trustedacissuers = new hashset();
        necessaryacattributes = new hashset();
        prohibitedacattributes = new hashset();
        attrcertcheckers = new hashset();
    }

    /**
     * returns an instance with the parameters of a given
     * <code>pkixparameters</code> object.
     * 
     * @param pkixparams the given <code>pkixparameters</code>
     * @return an extended pkix params object
     */
    public static extendedpkixparameters getinstance(pkixparameters pkixparams)
    {
        extendedpkixparameters params;
        try
        {
            params = new extendedpkixparameters(pkixparams.gettrustanchors());
        }
        catch (exception e)
        {
            // cannot happen
            throw new runtimeexception(e.getmessage());
        }
        params.setparams(pkixparams);
        return params;
    }

    /**
     * method to support <code>clone()</code> under j2me.
     * <code>super.clone()</code> does not exist and fields are not copied.
     * 
     * @param params parameters to set. if this are
     *            <code>extendedpkixparameters</code> they are copied to.
     */
    protected void setparams(pkixparameters params)
    {
        setdate(params.getdate());
        setcertpathcheckers(params.getcertpathcheckers());
        setcertstores(params.getcertstores());
        setanypolicyinhibited(params.isanypolicyinhibited());
        setexplicitpolicyrequired(params.isexplicitpolicyrequired());
        setpolicymappinginhibited(params.ispolicymappinginhibited());
        setrevocationenabled(params.isrevocationenabled());
        setinitialpolicies(params.getinitialpolicies());
        setpolicyqualifiersrejected(params.getpolicyqualifiersrejected());
        setsigprovider(params.getsigprovider());
        settargetcertconstraints(params.gettargetcertconstraints());
        try
        {
            settrustanchors(params.gettrustanchors());
        }
        catch (exception e)
        {
            // cannot happen
            throw new runtimeexception(e.getmessage());
        }
        if (params instanceof extendedpkixparameters)
        {
            extendedpkixparameters _params = (extendedpkixparameters) params;
            validitymodel = _params.validitymodel;
            usedeltas = _params.usedeltas;
            additionallocationsenabled = _params.additionallocationsenabled;
            selector = _params.selector == null ? null
                : (selector) _params.selector.clone();
            stores = new arraylist(_params.stores);
            additionalstores = new arraylist(_params.additionalstores);
            trustedacissuers = new hashset(_params.trustedacissuers);
            prohibitedacattributes = new hashset(_params.prohibitedacattributes);
            necessaryacattributes = new hashset(_params.necessaryacattributes);
            attrcertcheckers = new hashset(_params.attrcertcheckers);
        }
    }

    /**
     * this is the default pkix validity model. actually there are two variants
     * of this: the pkix model and the modified pkix model. the pkix model
     * verifies that all involved certificates must have been valid at the
     * current time. the modified pkix model verifies that all involved
     * certificates were valid at the signing time. both are indirectly choosen
     * with the {@link pkixparameters#setdate(java.util.date)} method, so this
     * methods sets the date when <em>all</em> certificates must have been
     * valid.
     */
    public static final int pkix_validity_model = 0;

    /**
     * this model uses the following validity model. each certificate must have
     * been valid at the moment where is was used. that means the end
     * certificate must have been valid at the time the signature was done. the
     * ca certificate which signed the end certificate must have been valid,
     * when the end certificate was signed. the ca (or root ca) certificate must
     * have been valid, when the ca certificate was signed and so on. so the
     * {@link pkixparameters#setdate(java.util.date)} method sets the time, when
     * the <em>end certificate</em> must have been valid. <p/> it is used e.g.
     * in the german signature law.
     */
    public static final int chain_validity_model = 1;

    private int validitymodel = pkix_validity_model;

    private boolean usedeltas = false;

    /**
     * defaults to <code>false</code>.
     * 
     * @return returns if delta crls should be used.
     */
    public boolean isusedeltasenabled()
    {
        return usedeltas;
    }

    /**
     * sets if delta crls should be used for checking the revocation status.
     * 
     * @param usedeltas <code>true</code> if delta crls should be used.
     */
    public void setusedeltasenabled(boolean usedeltas)
    {
        this.usedeltas = usedeltas;
    }

    /**
     * @return returns the validity model.
     * @see #chain_validity_model
     * @see #pkix_validity_model
     */
    public int getvaliditymodel()
    {
        return validitymodel;
    }

    /**
     * sets the java certstore to this extended pkix parameters.
     * 
     * @throws classcastexception if an element of <code>stores</code> is not
     *             a <code>certstore</code>.
     */
    public void setcertstores(list stores)
    {
        if (stores != null)
        {
            iterator it = stores.iterator();
            while (it.hasnext())
            {
                addcertstore((certstore)it.next());
            }
        }
    }

    /**
     * sets the bouncy castle stores for finding crls, certificates, attribute
     * certificates or cross certificates.
     * <p>
     * the <code>list</code> is cloned.
     * 
     * @param stores a list of stores to use.
     * @see #getstores
     * @throws classcastexception if an element of <code>stores</code> is not
     *             a {@link store}.
     */
    public void setstores(list stores)
    {
        if (stores == null)
        {
            this.stores = new arraylist();
        }
        else
        {
            for (iterator i = stores.iterator(); i.hasnext();)
            {
                if (!(i.next() instanceof store))
                {
                    throw new classcastexception(
                        "all elements of list must be "
                            + "of type org.bouncycastle.util.store.");
                }
            }
            this.stores = new arraylist(stores);
        }
    }

    /**
     * adds a bouncy castle {@link store} to find crls, certificates, attribute
     * certificates or cross certificates.
     * <p>
     * this method should be used to add local stores, like collection based
     * x.509 stores, if available. local stores should be considered first,
     * before trying to use additional (remote) locations, because they do not
     * need possible additional network traffic.
     * <p>
     * if <code>store</code> is <code>null</code> it is ignored.
     * 
     * @param store the store to add.
     * @see #getstores
     */
    public void addstore(store store)
    {
        if (store != null)
        {
            stores.add(store);
        }
    }

    /**
     * adds an additional bouncy castle {@link store} to find crls, certificates,
     * attribute certificates or cross certificates.
     * <p>
     * you should not use this method. this method is used for adding additional
     * x.509 stores, which are used to add (remote) locations, e.g. ldap, found
     * during x.509 object processing, e.g. in certificates or crls. this method
     * is used in pkix certification path processing.
     * <p>
     * if <code>store</code> is <code>null</code> it is ignored.
     * 
     * @param store the store to add.
     * @see #getstores()
     */
    public void addadditionalstore(store store)
    {
        if (store != null)
        {
            additionalstores.add(store);
        }
    }

    /**
     * @deprecated
     */
    public void addaddionalstore(store store)
    {
        addadditionalstore(store);      
    }

    /**
     * returns an immutable <code>list</code> of additional bouncy castle
     * <code>store</code>s used for finding crls, certificates, attribute
     * certificates or cross certificates.
     * 
     * @return an immutable <code>list</code> of additional bouncy castle
     *         <code>store</code>s. never <code>null</code>.
     * 
     * @see #addadditionalstore(store)
     */
    public list getadditionalstores()
    {
        return collections.unmodifiablelist(additionalstores);
    }

    /**
     * returns an immutable <code>list</code> of bouncy castle
     * <code>store</code>s used for finding crls, certificates, attribute
     * certificates or cross certificates.
     * 
     * @return an immutable <code>list</code> of bouncy castle
     *         <code>store</code>s. never <code>null</code>.
     * 
     * @see #setstores(list)
     */
    public list getstores()
    {
        return collections.unmodifiablelist(new arraylist(stores));
    }

    /**
     * @param validitymodel the validity model to set.
     * @see #chain_validity_model
     * @see #pkix_validity_model
     */
    public void setvaliditymodel(int validitymodel)
    {
        this.validitymodel = validitymodel;
    }

    public object clone()
    {
        extendedpkixparameters params;
        try
        {
            params = new extendedpkixparameters(gettrustanchors());
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
     * returns if additional {@link x509store}s for locations like ldap found
     * in certificates or crls should be used.
     * 
     * @return returns <code>true</code> if additional stores are used.
     */
    public boolean isadditionallocationsenabled()
    {
        return additionallocationsenabled;
    }

    /**
     * sets if additional {@link x509store}s for locations like ldap found in
     * certificates or crls should be used.
     * 
     * @param enabled <code>true</code> if additional stores are used.
     */
    public void setadditionallocationsenabled(boolean enabled)
    {
        additionallocationsenabled = enabled;
    }

    /**
     * returns the required constraints on the target certificate or attribute
     * certificate. the constraints are returned as an instance of
     * <code>selector</code>. if <code>null</code>, no constraints are
     * defined.
     * 
     * <p>
     * the target certificate in a pkix path may be a certificate or an
     * attribute certificate.
     * <p>
     * note that the <code>selector</code> returned is cloned to protect
     * against subsequent modifications.
     * 
     * @return a <code>selector</code> specifying the constraints on the
     *         target certificate or attribute certificate (or <code>null</code>)
     * @see #settargetconstraints
     * @see x509certstoreselector
     * @see x509attributecertstoreselector
     */
    public selector gettargetconstraints()
    {
        if (selector != null)
        {
            return (selector) selector.clone();
        }
        else
        {
            return null;
        }
    }

    /**
     * sets the required constraints on the target certificate or attribute
     * certificate. the constraints are specified as an instance of
     * <code>selector</code>. if <code>null</code>, no constraints are
     * defined.
     * <p>
     * the target certificate in a pkix path may be a certificate or an
     * attribute certificate.
     * <p>
     * note that the <code>selector</code> specified is cloned to protect
     * against subsequent modifications.
     * 
     * @param selector a <code>selector</code> specifying the constraints on
     *            the target certificate or attribute certificate (or
     *            <code>null</code>)
     * @see #gettargetconstraints
     * @see x509certstoreselector
     * @see x509attributecertstoreselector
     */
    public void settargetconstraints(selector selector)
    {
        if (selector != null)
        {
            this.selector = (selector) selector.clone();
        }
        else
        {
            this.selector = null;
        }
    }

    /**
     * sets the required constraints on the target certificate. the constraints
     * are specified as an instance of <code>x509certselector</code>. if
     * <code>null</code>, no constraints are defined.
     * 
     * <p>
     * this method wraps the given <code>x509certselector</code> into a
     * <code>x509certstoreselector</code>.
     * <p>
     * note that the <code>x509certselector</code> specified is cloned to
     * protect against subsequent modifications.
     * 
     * @param selector a <code>x509certselector</code> specifying the
     *            constraints on the target certificate (or <code>null</code>)
     * @see #gettargetcertconstraints
     * @see x509certstoreselector
     */
    public void settargetcertconstraints(certselector selector)
    {
        super.settargetcertconstraints(selector);
        if (selector != null)
        {
            this.selector = x509certstoreselector
                .getinstance((x509certselector) selector);
        }
        else
        {
            this.selector = null;
        }
    }

    /**
     * returns the trusted attribute certificate issuers. if attribute
     * certificates is verified the trusted ac issuers must be set.
     * <p>
     * the returned <code>set</code> consists of <code>trustanchor</code>s.
     * <p>
     * the returned <code>set</code> is immutable. never <code>null</code>
     * 
     * @return returns an immutable set of the trusted ac issuers.
     */
    public set gettrustedacissuers()
    {
        return collections.unmodifiableset(trustedacissuers);
    }

    /**
     * sets the trusted attribute certificate issuers. if attribute certificates
     * is verified the trusted ac issuers must be set.
     * <p>
     * the <code>trustedacissuers</code> must be a <code>set</code> of
     * <code>trustanchor</code>
     * <p>
     * the given set is cloned.
     * 
     * @param trustedacissuers the trusted ac issuers to set. is never
     *            <code>null</code>.
     * @throws classcastexception if an element of <code>stores</code> is not
     *             a <code>trustanchor</code>.
     */
    public void settrustedacissuers(set trustedacissuers)
    {
        if (trustedacissuers == null)
        {
            this.trustedacissuers.clear();
            return;
        }
        for (iterator it = trustedacissuers.iterator(); it.hasnext();)
        {
            if (!(it.next() instanceof trustanchor))
            {
                throw new classcastexception("all elements of set must be "
                    + "of type " + trustanchor.class.getname() + ".");
            }
        }
        this.trustedacissuers.clear();
        this.trustedacissuers.addall(trustedacissuers);
    }

    /**
     * returns the neccessary attributes which must be contained in an attribute
     * certificate.
     * <p>
     * the returned <code>set</code> is immutable and contains
     * <code>string</code>s with the oids.
     * 
     * @return returns the necessary ac attributes.
     */
    public set getnecessaryacattributes()
    {
        return collections.unmodifiableset(necessaryacattributes);
    }

    /**
     * sets the neccessary which must be contained in an attribute certificate.
     * <p>
     * the <code>set</code> must contain <code>string</code>s with the
     * oids.
     * <p>
     * the set is cloned.
     * 
     * @param necessaryacattributes the necessary ac attributes to set.
     * @throws classcastexception if an element of
     *             <code>necessaryacattributes</code> is not a
     *             <code>string</code>.
     */
    public void setnecessaryacattributes(set necessaryacattributes)
    {
        if (necessaryacattributes == null)
        {
            this.necessaryacattributes.clear();
            return;
        }
        for (iterator it = necessaryacattributes.iterator(); it.hasnext();)
        {
            if (!(it.next() instanceof string))
            {
                throw new classcastexception("all elements of set must be "
                    + "of type string.");
            }
        }
        this.necessaryacattributes.clear();
        this.necessaryacattributes.addall(necessaryacattributes);
    }

    /**
     * returns the attribute certificates which are not allowed.
     * <p>
     * the returned <code>set</code> is immutable and contains
     * <code>string</code>s with the oids.
     * 
     * @return returns the prohibited ac attributes. is never <code>null</code>.
     */
    public set getprohibitedacattributes()
    {
        return collections.unmodifiableset(prohibitedacattributes);
    }

    /**
     * sets the attribute certificates which are not allowed.
     * <p>
     * the <code>set</code> must contain <code>string</code>s with the
     * oids.
     * <p>
     * the set is cloned.
     * 
     * @param prohibitedacattributes the prohibited ac attributes to set.
     * @throws classcastexception if an element of
     *             <code>prohibitedacattributes</code> is not a
     *             <code>string</code>.
     */
    public void setprohibitedacattributes(set prohibitedacattributes)
    {
        if (prohibitedacattributes == null)
        {
            this.prohibitedacattributes.clear();
            return;
        }
        for (iterator it = prohibitedacattributes.iterator(); it.hasnext();)
        {
            if (!(it.next() instanceof string))
            {
                throw new classcastexception("all elements of set must be "
                    + "of type string.");
            }
        }
        this.prohibitedacattributes.clear();
        this.prohibitedacattributes.addall(prohibitedacattributes);
    }

    /**
     * returns the attribute certificate checker. the returned set contains
     * {@link pkixattrcertchecker}s and is immutable.
     * 
     * @return returns the attribute certificate checker. is never
     *         <code>null</code>.
     */
    public set getattrcertcheckers()
    {
        return collections.unmodifiableset(attrcertcheckers);
    }

    /**
     * sets the attribute certificate checkers.
     * <p>
     * all elements in the <code>set</code> must a {@link pkixattrcertchecker}.
     * <p>
     * the given set is cloned.
     * 
     * @param attrcertcheckers the attribute certificate checkers to set. is
     *            never <code>null</code>.
     * @throws classcastexception if an element of <code>attrcertcheckers</code>
     *             is not a <code>pkixattrcertchecker</code>.
     */
    public void setattrcertcheckers(set attrcertcheckers)
    {
        if (attrcertcheckers == null)
        {
            this.attrcertcheckers.clear();
            return;
        }
        for (iterator it = attrcertcheckers.iterator(); it.hasnext();)
        {
            if (!(it.next() instanceof pkixattrcertchecker))
            {
                throw new classcastexception("all elements of set must be "
                    + "of type " + pkixattrcertchecker.class.getname() + ".");
            }
        }
        this.attrcertcheckers.clear();
        this.attrcertcheckers.addall(attrcertcheckers);
    }

}
