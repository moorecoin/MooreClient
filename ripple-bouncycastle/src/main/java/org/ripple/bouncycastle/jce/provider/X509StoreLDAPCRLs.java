package org.ripple.bouncycastle.jce.provider;

import java.util.collection;
import java.util.collections;
import java.util.hashset;
import java.util.set;

import org.ripple.bouncycastle.jce.x509ldapcertstoreparameters;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.util.storeexception;
import org.ripple.bouncycastle.x509.x509crlstoreselector;
import org.ripple.bouncycastle.x509.x509storeparameters;
import org.ripple.bouncycastle.x509.x509storespi;
import org.ripple.bouncycastle.x509.util.ldapstorehelper;

/**
 * a spi implementation of bouncy castle <code>x509store</code> for getting
 * certificate revocation lists from an ldap directory.
 *
 * @see org.ripple.bouncycastle.x509.x509store
 */
public class x509storeldapcrls extends x509storespi
{

    private ldapstorehelper helper;

    public x509storeldapcrls()
    {
    }

    /**
     * initializes this ldap crl store implementation.
     *
     * @param params <code>x509ldapcertstoreparameters</code>.
     * @throws illegalargumentexception if <code>params</code> is not an instance of
     *                                  <code>x509ldapcertstoreparameters</code>.
     */
    public void engineinit(x509storeparameters params)
    {
        if (!(params instanceof x509ldapcertstoreparameters))
        {
            throw new illegalargumentexception(
                "initialization parameters must be an instance of "
                    + x509ldapcertstoreparameters.class.getname() + ".");
        }
        helper = new ldapstorehelper((x509ldapcertstoreparameters)params);
    }

    /**
     * returns a collection of matching crls from the ldap location.
     * <p/>
     * the selector must be a of type <code>x509crlstoreselector</code>. if
     * it is not an empty collection is returned.
     * <p/>
     * the issuer should be a reasonable criteria for a selector.
     *
     * @param selector the selector to use for finding.
     * @return a collection with the matches.
     * @throws storeexception if an exception occurs while searching.
     */
    public collection enginegetmatches(selector selector) throws storeexception
    {
        if (!(selector instanceof x509crlstoreselector))
        {
            return collections.empty_set;
        }
        x509crlstoreselector xselector = (x509crlstoreselector)selector;
        set set = new hashset();
        // test only delta crls should be selected
        if (xselector.isdeltacrlindicatorenabled())
        {
            set.addall(helper.getdeltacertificaterevocationlists(xselector));
        }
        // nothing specified
        else
        {
            set.addall(helper.getdeltacertificaterevocationlists(xselector));
            set.addall(helper.getattributeauthorityrevocationlists(xselector));
            set
                .addall(helper
                    .getattributecertificaterevocationlists(xselector));
            set.addall(helper.getauthorityrevocationlists(xselector));
            set.addall(helper.getcertificaterevocationlists(xselector));
        }
        return set;
    }
}
