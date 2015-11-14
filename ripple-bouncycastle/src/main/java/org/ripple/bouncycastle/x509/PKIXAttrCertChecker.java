package org.ripple.bouncycastle.x509;

import java.security.cert.certpath;
import java.security.cert.certpathvalidatorexception;
import java.util.collection;
import java.util.set;

public abstract class pkixattrcertchecker
    implements cloneable
{

    /**
     * returns an immutable <code>set</code> of x.509 attribute certificate
     * extensions that this <code>pkixattrcertchecker</code> supports or
     * <code>null</code> if no extensions are supported.
     * <p>
     * each element of the set is a <code>string</code> representing the
     * object identifier (oid) of the x.509 extension that is supported.
     * <p>
     * all x.509 attribute certificate extensions that a
     * <code>pkixattrcertchecker</code> might possibly be able to process
     * should be included in the set.
     * 
     * @return an immutable <code>set</code> of x.509 extension oids (in
     *         <code>string</code> format) supported by this
     *         <code>pkixattrcertchecker</code>, or <code>null</code> if no
     *         extensions are supported
     */
    public abstract set getsupportedextensions();

    /**
     * performs checks on the specified attribute certificate. every handled
     * extension is rmeoved from the <code>unresolvedcritexts</code>
     * collection.
     * 
     * @param attrcert the attribute certificate to be checked.
     * @param certpath the certificate path which belongs to the attribute
     *            certificate issuer public key certificate.
     * @param holdercertpath the certificate path which belongs to the holder
     *            certificate.
     * @param unresolvedcritexts a <code>collection</code> of oid strings
     *            representing the current set of unresolved critical extensions
     * @throws certpathvalidatorexception if the specified attribute certificate
     *             does not pass the check.
     */
    public abstract void check(x509attributecertificate attrcert, certpath certpath,
                                 certpath holdercertpath, collection unresolvedcritexts)
        throws certpathvalidatorexception;

    /**
     * returns a clone of this object.
     * 
     * @return a copy of this <code>pkixattrcertchecker</code>
     */
    public abstract object clone();
}
