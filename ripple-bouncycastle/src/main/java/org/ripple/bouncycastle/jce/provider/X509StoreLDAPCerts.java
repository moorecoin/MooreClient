package org.ripple.bouncycastle.jce.provider;

import java.util.collection;
import java.util.collections;
import java.util.hashset;
import java.util.iterator;
import java.util.set;

import org.ripple.bouncycastle.jce.x509ldapcertstoreparameters;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.util.storeexception;
import org.ripple.bouncycastle.x509.x509certpairstoreselector;
import org.ripple.bouncycastle.x509.x509certstoreselector;
import org.ripple.bouncycastle.x509.x509certificatepair;
import org.ripple.bouncycastle.x509.x509storeparameters;
import org.ripple.bouncycastle.x509.x509storespi;
import org.ripple.bouncycastle.x509.util.ldapstorehelper;

/**
 * a spi implementation of bouncy castle <code>x509store</code> for getting
 * certificates form a ldap directory.
 *
 * @see org.ripple.bouncycastle.x509.x509store
 */
public class x509storeldapcerts
    extends x509storespi
{

    private ldapstorehelper helper;

    public x509storeldapcerts()
    {
    }

    /**
     * initializes this ldap cert store implementation.
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
     * returns a collection of matching certificates from the ldap location.
     * <p/>
     * the selector must be a of type <code>x509certstoreselector</code>. if
     * it is not an empty collection is returned.
     * <p/>
     * the implementation searches only for ca certificates, if the method
     * {@link java.security.cert.x509certselector#getbasicconstraints()} is
     * greater or equal to 0. if it is -2 only end certificates are searched.
     * <p/>
     * the subject and the serial number for end certificates should be
     * reasonable criterias for a selector.
     *
     * @param selector the selector to use for finding.
     * @return a collection with the matches.
     * @throws storeexception if an exception occurs while searching.
     */
    public collection enginegetmatches(selector selector) throws storeexception
    {
        if (!(selector instanceof x509certstoreselector))
        {
            return collections.empty_set;
        }
        x509certstoreselector xselector = (x509certstoreselector)selector;
        set set = new hashset();
        // test if only ca certificates should be selected
        if (xselector.getbasicconstraints() > 0)
        {
            set.addall(helper.getcacertificates(xselector));
            set.addall(getcertificatesfromcrosscertificatepairs(xselector));
        }
        // only end certificates should be selected
        else if (xselector.getbasicconstraints() == -2)
        {
            set.addall(helper.getusercertificates(xselector));
        }
        // nothing specified
        else
        {
            set.addall(helper.getusercertificates(xselector));
            set.addall(helper.getcacertificates(xselector));
            set.addall(getcertificatesfromcrosscertificatepairs(xselector));
        }
        return set;
    }

    private collection getcertificatesfromcrosscertificatepairs(
        x509certstoreselector xselector) throws storeexception
    {
        set set = new hashset();
        x509certpairstoreselector ps = new x509certpairstoreselector();

        ps.setforwardselector(xselector);
        ps.setreverseselector(new x509certstoreselector());
        
        set crosscerts = new hashset(helper.getcrosscertificatepairs(ps));
        set forward = new hashset();
        set reverse = new hashset();
        iterator it = crosscerts.iterator();
        while (it.hasnext())
        {
            x509certificatepair pair = (x509certificatepair)it.next();
            if (pair.getforward() != null)
            {
                forward.add(pair.getforward());
            }
            if (pair.getreverse() != null)
            {
                reverse.add(pair.getreverse());
            }
        }
        set.addall(forward);
        set.addall(reverse);
        return set;
    }
}
