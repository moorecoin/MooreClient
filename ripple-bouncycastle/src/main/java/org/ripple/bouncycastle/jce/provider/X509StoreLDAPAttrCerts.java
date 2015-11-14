package org.ripple.bouncycastle.jce.provider;

import java.util.collection;
import java.util.collections;
import java.util.hashset;
import java.util.set;

import org.ripple.bouncycastle.jce.x509ldapcertstoreparameters;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.util.storeexception;
import org.ripple.bouncycastle.x509.x509attributecertstoreselector;
import org.ripple.bouncycastle.x509.x509storeparameters;
import org.ripple.bouncycastle.x509.x509storespi;
import org.ripple.bouncycastle.x509.util.ldapstorehelper;

/**
 * a spi implementation of bouncy castle <code>x509store</code> for getting
 * attribute certificates from an ldap directory.
 *
 * @see org.ripple.bouncycastle.x509.x509store
 */
public class x509storeldapattrcerts extends x509storespi
{

    private ldapstorehelper helper;

    public x509storeldapattrcerts()
    {
    }

    /**
     * initializes this ldap attribute cert store implementation.
     *
     * @param parameters <code>x509ldapcertstoreparameters</code>.
     * @throws illegalargumentexception if <code>params</code> is not an instance of
     *                                  <code>x509ldapcertstoreparameters</code>.
     */
    public void engineinit(x509storeparameters parameters)
    {
        if (!(parameters instanceof x509ldapcertstoreparameters))
        {
            throw new illegalargumentexception(
                "initialization parameters must be an instance of "
                    + x509ldapcertstoreparameters.class.getname() + ".");
        }
        helper = new ldapstorehelper((x509ldapcertstoreparameters)parameters);
    }

    /**
     * returns a collection of matching attribute certificates from the ldap
     * location.
     * <p/>
     * the selector must be a of type
     * <code>x509attributecertstoreselector</code>. if it is not an empty
     * collection is returned.
     * <p/>
     * <p/>
     * the subject and the serial number should be reasonable criterias for a
     * selector.
     *
     * @param selector the selector to use for finding.
     * @return a collection with the matches.
     * @throws storeexception if an exception occurs while searching.
     */
    public collection enginegetmatches(selector selector) throws storeexception
    {
        if (!(selector instanceof x509attributecertstoreselector))
        {
            return collections.empty_set;
        }
        x509attributecertstoreselector xselector = (x509attributecertstoreselector)selector;
        set set = new hashset();
        set.addall(helper.getaacertificates(xselector));
        set.addall(helper.getattributecertificateattributes(xselector));
        set.addall(helper.getattributedescriptorcertificates(xselector));
        return set;
    }

}
