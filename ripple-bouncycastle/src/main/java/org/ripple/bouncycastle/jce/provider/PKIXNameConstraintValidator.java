package org.ripple.bouncycastle.jce.provider;

import java.util.collection;
import java.util.collections;
import java.util.hashmap;
import java.util.hashset;
import java.util.iterator;
import java.util.map;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalsubtree;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.util.strings;

public class pkixnameconstraintvalidator
{
    private set excludedsubtreesdn = new hashset();

    private set excludedsubtreesdns = new hashset();

    private set excludedsubtreesemail = new hashset();

    private set excludedsubtreesuri = new hashset();

    private set excludedsubtreesip = new hashset();

    private set permittedsubtreesdn;

    private set permittedsubtreesdns;

    private set permittedsubtreesemail;

    private set permittedsubtreesuri;

    private set permittedsubtreesip;

    public pkixnameconstraintvalidator()
    {
    }

    private static boolean withindnsubtree(
        asn1sequence dns,
        asn1sequence subtree)
    {
        if (subtree.size() < 1)
        {
            return false;
        }

        if (subtree.size() > dns.size())
        {
            return false;
        }

        for (int j = subtree.size() - 1; j >= 0; j--)
        {
            if (!subtree.getobjectat(j).equals(dns.getobjectat(j)))
            {
                return false;
            }
        }

        return true;
    }

    public void checkpermitteddn(asn1sequence dns)
        throws pkixnameconstraintvalidatorexception
    {
        checkpermitteddn(permittedsubtreesdn, dns);
    }

    public void checkexcludeddn(asn1sequence dns)
        throws pkixnameconstraintvalidatorexception
    {
        checkexcludeddn(excludedsubtreesdn, dns);
    }

    private void checkpermitteddn(set permitted, asn1sequence dns)
        throws pkixnameconstraintvalidatorexception
    {
        if (permitted == null)
        {
            return;
        }

        if (permitted.isempty() && dns.size() == 0)
        {
            return;
        }
        iterator it = permitted.iterator();

        while (it.hasnext())
        {
            asn1sequence subtree = (asn1sequence)it.next();

            if (withindnsubtree(dns, subtree))
            {
                return;
            }
        }

        throw new pkixnameconstraintvalidatorexception(
            "subject distinguished name is not from a permitted subtree");
    }

    private void checkexcludeddn(set excluded, asn1sequence dns)
        throws pkixnameconstraintvalidatorexception
    {
        if (excluded.isempty())
        {
            return;
        }

        iterator it = excluded.iterator();

        while (it.hasnext())
        {
            asn1sequence subtree = (asn1sequence)it.next();

            if (withindnsubtree(dns, subtree))
            {
                throw new pkixnameconstraintvalidatorexception(
                    "subject distinguished name is from an excluded subtree");
            }
        }
    }

    private set intersectdn(set permitted, set dns)
    {
        set intersect = new hashset();
        for (iterator it = dns.iterator(); it.hasnext();)
        {
            asn1sequence dn = asn1sequence.getinstance(((generalsubtree)it
                .next()).getbase().getname().toasn1primitive());
            if (permitted == null)
            {
                if (dn != null)
                {
                    intersect.add(dn);
                }
            }
            else
            {
                iterator _iter = permitted.iterator();
                while (_iter.hasnext())
                {
                    asn1sequence subtree = (asn1sequence)_iter.next();

                    if (withindnsubtree(dn, subtree))
                    {
                        intersect.add(dn);
                    }
                    else if (withindnsubtree(subtree, dn))
                    {
                        intersect.add(subtree);
                    }
                }
            }
        }
        return intersect;
    }

    private set uniondn(set excluded, asn1sequence dn)
    {
        if (excluded.isempty())
        {
            if (dn == null)
            {
                return excluded;
            }
            excluded.add(dn);

            return excluded;
        }
        else
        {
            set intersect = new hashset();

            iterator it = excluded.iterator();
            while (it.hasnext())
            {
                asn1sequence subtree = (asn1sequence)it.next();

                if (withindnsubtree(dn, subtree))
                {
                    intersect.add(subtree);
                }
                else if (withindnsubtree(subtree, dn))
                {
                    intersect.add(dn);
                }
                else
                {
                    intersect.add(subtree);
                    intersect.add(dn);
                }
            }

            return intersect;
        }
    }

    private set intersectemail(set permitted, set emails)
    {
        set intersect = new hashset();
        for (iterator it = emails.iterator(); it.hasnext();)
        {
            string email = extractnameasstring(((generalsubtree)it.next())
                .getbase());

            if (permitted == null)
            {
                if (email != null)
                {
                    intersect.add(email);
                }
            }
            else
            {
                iterator it2 = permitted.iterator();
                while (it2.hasnext())
                {
                    string _permitted = (string)it2.next();

                    intersectemail(email, _permitted, intersect);
                }
            }
        }
        return intersect;
    }

    private set unionemail(set excluded, string email)
    {
        if (excluded.isempty())
        {
            if (email == null)
            {
                return excluded;
            }
            excluded.add(email);
            return excluded;
        }
        else
        {
            set union = new hashset();

            iterator it = excluded.iterator();
            while (it.hasnext())
            {
                string _excluded = (string)it.next();

                unionemail(_excluded, email, union);
            }

            return union;
        }
    }

    /**
     * returns the intersection of the permitted ip ranges in
     * <code>permitted</code> with <code>ip</code>.
     *
     * @param permitted a <code>set</code> of permitted ip addresses with
     *                  their subnet mask as byte arrays.
     * @param ips       the ip address with its subnet mask.
     * @return the <code>set</code> of permitted ip ranges intersected with
     *         <code>ip</code>.
     */
    private set intersectip(set permitted, set ips)
    {
        set intersect = new hashset();
        for (iterator it = ips.iterator(); it.hasnext();)
        {
            byte[] ip = asn1octetstring.getinstance(
                ((generalsubtree)it.next()).getbase().getname()).getoctets();
            if (permitted == null)
            {
                if (ip != null)
                {
                    intersect.add(ip);
                }
            }
            else
            {
                iterator it2 = permitted.iterator();
                while (it2.hasnext())
                {
                    byte[] _permitted = (byte[])it2.next();
                    intersect.addall(intersectiprange(_permitted, ip));
                }
            }
        }
        return intersect;
    }

    /**
     * returns the union of the excluded ip ranges in <code>excluded</code>
     * with <code>ip</code>.
     *
     * @param excluded a <code>set</code> of excluded ip addresses with their
     *                 subnet mask as byte arrays.
     * @param ip       the ip address with its subnet mask.
     * @return the <code>set</code> of excluded ip ranges unified with
     *         <code>ip</code> as byte arrays.
     */
    private set unionip(set excluded, byte[] ip)
    {
        if (excluded.isempty())
        {
            if (ip == null)
            {
                return excluded;
            }
            excluded.add(ip);

            return excluded;
        }
        else
        {
            set union = new hashset();

            iterator it = excluded.iterator();
            while (it.hasnext())
            {
                byte[] _excluded = (byte[])it.next();
                union.addall(unioniprange(_excluded, ip));
            }

            return union;
        }
    }

    /**
     * calculates the union if two ip ranges.
     *
     * @param ipwithsubmask1 the first ip address with its subnet mask.
     * @param ipwithsubmask2 the second ip address with its subnet mask.
     * @return a <code>set</code> with the union of both addresses.
     */
    private set unioniprange(byte[] ipwithsubmask1, byte[] ipwithsubmask2)
    {
        set set = new hashset();

        // difficult, adding always all ips is not wrong
        if (arrays.areequal(ipwithsubmask1, ipwithsubmask2))
        {
            set.add(ipwithsubmask1);
        }
        else
        {
            set.add(ipwithsubmask1);
            set.add(ipwithsubmask2);
        }
        return set;
    }

    /**
     * calculates the interesction if two ip ranges.
     *
     * @param ipwithsubmask1 the first ip address with its subnet mask.
     * @param ipwithsubmask2 the second ip address with its subnet mask.
     * @return a <code>set</code> with the single ip address with its subnet
     *         mask as a byte array or an empty <code>set</code>.
     */
    private set intersectiprange(byte[] ipwithsubmask1, byte[] ipwithsubmask2)
    {
        if (ipwithsubmask1.length != ipwithsubmask2.length)
        {
            return collections.empty_set;
        }
        byte[][] temp = extractipsandsubnetmasks(ipwithsubmask1, ipwithsubmask2);
        byte ip1[] = temp[0];
        byte subnetmask1[] = temp[1];
        byte ip2[] = temp[2];
        byte subnetmask2[] = temp[3];

        byte minmax[][] = minmaxips(ip1, subnetmask1, ip2, subnetmask2);
        byte[] min;
        byte[] max;
        max = min(minmax[1], minmax[3]);
        min = max(minmax[0], minmax[2]);

        // minimum ip address must be bigger than max
        if (compareto(min, max) == 1)
        {
            return collections.empty_set;
        }
        // or keeps all significant bits
        byte[] ip = or(minmax[0], minmax[2]);
        byte[] subnetmask = or(subnetmask1, subnetmask2);
        return collections.singleton(ipwithsubnetmask(ip, subnetmask));
    }

    /**
     * concatenates the ip address with its subnet mask.
     *
     * @param ip         the ip address.
     * @param subnetmask its subnet mask.
     * @return the concatenated ip address with its subnet mask.
     */
    private byte[] ipwithsubnetmask(byte[] ip, byte[] subnetmask)
    {
        int iplength = ip.length;
        byte[] temp = new byte[iplength * 2];
        system.arraycopy(ip, 0, temp, 0, iplength);
        system.arraycopy(subnetmask, 0, temp, iplength, iplength);
        return temp;
    }

    /**
     * splits the ip addresses and their subnet mask.
     *
     * @param ipwithsubmask1 the first ip address with the subnet mask.
     * @param ipwithsubmask2 the second ip address with the subnet mask.
     * @return an array with two elements. each element contains the ip address
     *         and the subnet mask in this order.
     */
    private byte[][] extractipsandsubnetmasks(
        byte[] ipwithsubmask1,
        byte[] ipwithsubmask2)
    {
        int iplength = ipwithsubmask1.length / 2;
        byte ip1[] = new byte[iplength];
        byte subnetmask1[] = new byte[iplength];
        system.arraycopy(ipwithsubmask1, 0, ip1, 0, iplength);
        system.arraycopy(ipwithsubmask1, iplength, subnetmask1, 0, iplength);

        byte ip2[] = new byte[iplength];
        byte subnetmask2[] = new byte[iplength];
        system.arraycopy(ipwithsubmask2, 0, ip2, 0, iplength);
        system.arraycopy(ipwithsubmask2, iplength, subnetmask2, 0, iplength);
        return new byte[][]
            {ip1, subnetmask1, ip2, subnetmask2};
    }

    /**
     * based on the two ip addresses and their subnet masks the ip range is
     * computed for each ip address - subnet mask pair and returned as the
     * minimum ip address and the maximum address of the range.
     *
     * @param ip1         the first ip address.
     * @param subnetmask1 the subnet mask of the first ip address.
     * @param ip2         the second ip address.
     * @param subnetmask2 the subnet mask of the second ip address.
     * @return a array with two elements. the first/second element contains the
     *         min and max ip address of the first/second ip address and its
     *         subnet mask.
     */
    private byte[][] minmaxips(
        byte[] ip1,
        byte[] subnetmask1,
        byte[] ip2,
        byte[] subnetmask2)
    {
        int iplength = ip1.length;
        byte[] min1 = new byte[iplength];
        byte[] max1 = new byte[iplength];

        byte[] min2 = new byte[iplength];
        byte[] max2 = new byte[iplength];

        for (int i = 0; i < iplength; i++)
        {
            min1[i] = (byte)(ip1[i] & subnetmask1[i]);
            max1[i] = (byte)(ip1[i] & subnetmask1[i] | ~subnetmask1[i]);

            min2[i] = (byte)(ip2[i] & subnetmask2[i]);
            max2[i] = (byte)(ip2[i] & subnetmask2[i] | ~subnetmask2[i]);
        }

        return new byte[][]{min1, max1, min2, max2};
    }

    private void checkpermittedemail(set permitted, string email)
        throws pkixnameconstraintvalidatorexception
    {
        if (permitted == null)
        {
            return;
        }

        iterator it = permitted.iterator();

        while (it.hasnext())
        {
            string str = ((string)it.next());

            if (emailisconstrained(email, str))
            {
                return;
            }
        }

        if (email.length() == 0 && permitted.size() == 0)
        {
            return;
        }

        throw new pkixnameconstraintvalidatorexception(
            "subject email address is not from a permitted subtree.");
    }

    private void checkexcludedemail(set excluded, string email)
        throws pkixnameconstraintvalidatorexception
    {
        if (excluded.isempty())
        {
            return;
        }

        iterator it = excluded.iterator();

        while (it.hasnext())
        {
            string str = (string)it.next();

            if (emailisconstrained(email, str))
            {
                throw new pkixnameconstraintvalidatorexception(
                    "email address is from an excluded subtree.");
            }
        }
    }

    /**
     * checks if the ip <code>ip</code> is included in the permitted set
     * <code>permitted</code>.
     *
     * @param permitted a <code>set</code> of permitted ip addresses with
     *                  their subnet mask as byte arrays.
     * @param ip        the ip address.
     * @throws pkixnameconstraintvalidatorexception
     *          if the ip is not permitted.
     */
    private void checkpermittedip(set permitted, byte[] ip)
        throws pkixnameconstraintvalidatorexception
    {
        if (permitted == null)
        {
            return;
        }

        iterator it = permitted.iterator();

        while (it.hasnext())
        {
            byte[] ipwithsubnet = (byte[])it.next();

            if (isipconstrained(ip, ipwithsubnet))
            {
                return;
            }
        }
        if (ip.length == 0 && permitted.size() == 0)
        {
            return;
        }
        throw new pkixnameconstraintvalidatorexception(
            "ip is not from a permitted subtree.");
    }

    /**
     * checks if the ip <code>ip</code> is included in the excluded set
     * <code>excluded</code>.
     *
     * @param excluded a <code>set</code> of excluded ip addresses with their
     *                 subnet mask as byte arrays.
     * @param ip       the ip address.
     * @throws pkixnameconstraintvalidatorexception
     *          if the ip is excluded.
     */
    private void checkexcludedip(set excluded, byte[] ip)
        throws pkixnameconstraintvalidatorexception
    {
        if (excluded.isempty())
        {
            return;
        }

        iterator it = excluded.iterator();

        while (it.hasnext())
        {
            byte[] ipwithsubnet = (byte[])it.next();

            if (isipconstrained(ip, ipwithsubnet))
            {
                throw new pkixnameconstraintvalidatorexception(
                    "ip is from an excluded subtree.");
            }
        }
    }

    /**
     * checks if the ip address <code>ip</code> is constrained by
     * <code>constraint</code>.
     *
     * @param ip         the ip address.
     * @param constraint the constraint. this is an ip address concatenated with
     *                   its subnetmask.
     * @return <code>true</code> if constrained, <code>false</code>
     *         otherwise.
     */
    private boolean isipconstrained(byte ip[], byte[] constraint)
    {
        int iplength = ip.length;

        if (iplength != (constraint.length / 2))
        {
            return false;
        }

        byte[] subnetmask = new byte[iplength];
        system.arraycopy(constraint, iplength, subnetmask, 0, iplength);

        byte[] permittedsubnetaddress = new byte[iplength];

        byte[] ipsubnetaddress = new byte[iplength];

        // the resulting ip address by applying the subnet mask
        for (int i = 0; i < iplength; i++)
        {
            permittedsubnetaddress[i] = (byte)(constraint[i] & subnetmask[i]);
            ipsubnetaddress[i] = (byte)(ip[i] & subnetmask[i]);
        }

        return arrays.areequal(permittedsubnetaddress, ipsubnetaddress);
    }

    private boolean emailisconstrained(string email, string constraint)
    {
        string sub = email.substring(email.indexof('@') + 1);
        // a particular mailbox
        if (constraint.indexof('@') != -1)
        {
            if (email.equalsignorecase(constraint))
            {
                return true;
            }
        }
        // on particular host
        else if (!(constraint.charat(0) == '.'))
        {
            if (sub.equalsignorecase(constraint))
            {
                return true;
            }
        }
        // address in sub domain
        else if (withindomain(sub, constraint))
        {
            return true;
        }
        return false;
    }

    private boolean withindomain(string testdomain, string domain)
    {
        string tempdomain = domain;
        if (tempdomain.startswith("."))
        {
            tempdomain = tempdomain.substring(1);
        }
        string[] domainparts = strings.split(tempdomain, '.');
        string[] testdomainparts = strings.split(testdomain, '.');
        // must have at least one subdomain
        if (testdomainparts.length <= domainparts.length)
        {
            return false;
        }
        int d = testdomainparts.length - domainparts.length;
        for (int i = -1; i < domainparts.length; i++)
        {
            if (i == -1)
            {
                if (testdomainparts[i + d].equals(""))
                {
                    return false;
                }
            }
            else if (!domainparts[i].equalsignorecase(testdomainparts[i + d]))
            {
                return false;
            }
        }
        return true;
    }

    private void checkpermitteddns(set permitted, string dns)
        throws pkixnameconstraintvalidatorexception
    {
        if (permitted == null)
        {
            return;
        }

        iterator it = permitted.iterator();

        while (it.hasnext())
        {
            string str = ((string)it.next());

            // is sub domain
            if (withindomain(dns, str) || dns.equalsignorecase(str))
            {
                return;
            }
        }
        if (dns.length() == 0 && permitted.size() == 0)
        {
            return;
        }
        throw new pkixnameconstraintvalidatorexception(
            "dns is not from a permitted subtree.");
    }

    private void checkexcludeddns(set excluded, string dns)
        throws pkixnameconstraintvalidatorexception
    {
        if (excluded.isempty())
        {
            return;
        }

        iterator it = excluded.iterator();

        while (it.hasnext())
        {
            string str = ((string)it.next());

            // is sub domain or the same
            if (withindomain(dns, str) || dns.equalsignorecase(str))
            {
                throw new pkixnameconstraintvalidatorexception(
                    "dns is from an excluded subtree.");
            }
        }
    }

    /**
     * the common part of <code>email1</code> and <code>email2</code> is
     * added to the union <code>union</code>. if <code>email1</code> and
     * <code>email2</code> have nothing in common they are added both.
     *
     * @param email1 email address constraint 1.
     * @param email2 email address constraint 2.
     * @param union  the union.
     */
    private void unionemail(string email1, string email2, set union)
    {
        // email1 is a particular address
        if (email1.indexof('@') != -1)
        {
            string _sub = email1.substring(email1.indexof('@') + 1);
            // both are a particular mailbox
            if (email2.indexof('@') != -1)
            {
                if (email1.equalsignorecase(email2))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(_sub, email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsignorecase(email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
        // email1 specifies a domain
        else if (email1.startswith("."))
        {
            if (email2.indexof('@') != -1)
            {
                string _sub = email2.substring(email1.indexof('@') + 1);
                if (withindomain(_sub, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(email1, email2)
                    || email1.equalsignorecase(email2))
                {
                    union.add(email2);
                }
                else if (withindomain(email2, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            else
            {
                if (withindomain(email2, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
        // email specifies a host
        else
        {
            if (email2.indexof('@') != -1)
            {
                string _sub = email2.substring(email1.indexof('@') + 1);
                if (_sub.equalsignorecase(email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(email1, email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsignorecase(email2))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
    }

    private void unionuri(string email1, string email2, set union)
    {
        // email1 is a particular address
        if (email1.indexof('@') != -1)
        {
            string _sub = email1.substring(email1.indexof('@') + 1);
            // both are a particular mailbox
            if (email2.indexof('@') != -1)
            {
                if (email1.equalsignorecase(email2))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(_sub, email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsignorecase(email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
        // email1 specifies a domain
        else if (email1.startswith("."))
        {
            if (email2.indexof('@') != -1)
            {
                string _sub = email2.substring(email1.indexof('@') + 1);
                if (withindomain(_sub, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(email1, email2)
                    || email1.equalsignorecase(email2))
                {
                    union.add(email2);
                }
                else if (withindomain(email2, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            else
            {
                if (withindomain(email2, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
        // email specifies a host
        else
        {
            if (email2.indexof('@') != -1)
            {
                string _sub = email2.substring(email1.indexof('@') + 1);
                if (_sub.equalsignorecase(email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(email1, email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsignorecase(email2))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
    }

    private set intersectdns(set permitted, set dnss)
    {
        set intersect = new hashset();
        for (iterator it = dnss.iterator(); it.hasnext();)
        {
            string dns = extractnameasstring(((generalsubtree)it.next())
                .getbase());
            if (permitted == null)
            {
                if (dns != null)
                {
                    intersect.add(dns);
                }
            }
            else
            {
                iterator _iter = permitted.iterator();
                while (_iter.hasnext())
                {
                    string _permitted = (string)_iter.next();

                    if (withindomain(_permitted, dns))
                    {
                        intersect.add(_permitted);
                    }
                    else if (withindomain(dns, _permitted))
                    {
                        intersect.add(dns);
                    }
                }
            }
        }

        return intersect;
    }

    protected set uniondns(set excluded, string dns)
    {
        if (excluded.isempty())
        {
            if (dns == null)
            {
                return excluded;
            }
            excluded.add(dns);

            return excluded;
        }
        else
        {
            set union = new hashset();

            iterator _iter = excluded.iterator();
            while (_iter.hasnext())
            {
                string _permitted = (string)_iter.next();

                if (withindomain(_permitted, dns))
                {
                    union.add(dns);
                }
                else if (withindomain(dns, _permitted))
                {
                    union.add(_permitted);
                }
                else
                {
                    union.add(_permitted);
                    union.add(dns);
                }
            }

            return union;
        }
    }

    /**
     * the most restricting part from <code>email1</code> and
     * <code>email2</code> is added to the intersection <code>intersect</code>.
     *
     * @param email1    email address constraint 1.
     * @param email2    email address constraint 2.
     * @param intersect the intersection.
     */
    private void intersectemail(string email1, string email2, set intersect)
    {
        // email1 is a particular address
        if (email1.indexof('@') != -1)
        {
            string _sub = email1.substring(email1.indexof('@') + 1);
            // both are a particular mailbox
            if (email2.indexof('@') != -1)
            {
                if (email1.equalsignorecase(email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(_sub, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsignorecase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
        // email specifies a domain
        else if (email1.startswith("."))
        {
            if (email2.indexof('@') != -1)
            {
                string _sub = email2.substring(email1.indexof('@') + 1);
                if (withindomain(_sub, email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(email1, email2)
                    || email1.equalsignorecase(email2))
                {
                    intersect.add(email1);
                }
                else if (withindomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
            else
            {
                if (withindomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
        }
        // email1 specifies a host
        else
        {
            if (email2.indexof('@') != -1)
            {
                string _sub = email2.substring(email2.indexof('@') + 1);
                if (_sub.equalsignorecase(email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(email1, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsignorecase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
    }

    private void checkexcludeduri(set excluded, string uri)
        throws pkixnameconstraintvalidatorexception
    {
        if (excluded.isempty())
        {
            return;
        }

        iterator it = excluded.iterator();

        while (it.hasnext())
        {
            string str = ((string)it.next());

            if (isuriconstrained(uri, str))
            {
                throw new pkixnameconstraintvalidatorexception(
                    "uri is from an excluded subtree.");
            }
        }
    }

    private set intersecturi(set permitted, set uris)
    {
        set intersect = new hashset();
        for (iterator it = uris.iterator(); it.hasnext();)
        {
            string uri = extractnameasstring(((generalsubtree)it.next())
                .getbase());
            if (permitted == null)
            {
                if (uri != null)
                {
                    intersect.add(uri);
                }
            }
            else
            {
                iterator _iter = permitted.iterator();
                while (_iter.hasnext())
                {
                    string _permitted = (string)_iter.next();
                    intersecturi(_permitted, uri, intersect);
                }
            }
        }
        return intersect;
    }

    private set unionuri(set excluded, string uri)
    {
        if (excluded.isempty())
        {
            if (uri == null)
            {
                return excluded;
            }
            excluded.add(uri);

            return excluded;
        }
        else
        {
            set union = new hashset();

            iterator _iter = excluded.iterator();
            while (_iter.hasnext())
            {
                string _excluded = (string)_iter.next();

                unionuri(_excluded, uri, union);
            }

            return union;
        }
    }

    private void intersecturi(string email1, string email2, set intersect)
    {
        // email1 is a particular address
        if (email1.indexof('@') != -1)
        {
            string _sub = email1.substring(email1.indexof('@') + 1);
            // both are a particular mailbox
            if (email2.indexof('@') != -1)
            {
                if (email1.equalsignorecase(email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(_sub, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsignorecase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
        // email specifies a domain
        else if (email1.startswith("."))
        {
            if (email2.indexof('@') != -1)
            {
                string _sub = email2.substring(email1.indexof('@') + 1);
                if (withindomain(_sub, email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(email1, email2)
                    || email1.equalsignorecase(email2))
                {
                    intersect.add(email1);
                }
                else if (withindomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
            else
            {
                if (withindomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
        }
        // email1 specifies a host
        else
        {
            if (email2.indexof('@') != -1)
            {
                string _sub = email2.substring(email2.indexof('@') + 1);
                if (_sub.equalsignorecase(email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startswith("."))
            {
                if (withindomain(email1, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsignorecase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
    }

    private void checkpermitteduri(set permitted, string uri)
        throws pkixnameconstraintvalidatorexception
    {
        if (permitted == null)
        {
            return;
        }

        iterator it = permitted.iterator();

        while (it.hasnext())
        {
            string str = ((string)it.next());

            if (isuriconstrained(uri, str))
            {
                return;
            }
        }
        if (uri.length() == 0 && permitted.size() == 0)
        {
            return;
        }
        throw new pkixnameconstraintvalidatorexception(
            "uri is not from a permitted subtree.");
    }

    private boolean isuriconstrained(string uri, string constraint)
    {
        string host = extracthostfromurl(uri);
        // a host
        if (!constraint.startswith("."))
        {
            if (host.equalsignorecase(constraint))
            {
                return true;
            }
        }

        // in sub domain or domain
        else if (withindomain(host, constraint))
        {
            return true;
        }

        return false;
    }

    private static string extracthostfromurl(string url)
    {
        // see rfc 1738
        // remove ':' after protocol, e.g. http:
        string sub = url.substring(url.indexof(':') + 1);
        // extract host from common internet scheme syntax, e.g. http://
        if (sub.indexof("//") != -1)
        {
            sub = sub.substring(sub.indexof("//") + 2);
        }
        // first remove port, e.g. http://test.com:21
        if (sub.lastindexof(':') != -1)
        {
            sub = sub.substring(0, sub.lastindexof(':'));
        }
        // remove user and password, e.g. http://john:password@test.com
        sub = sub.substring(sub.indexof(':') + 1);
        sub = sub.substring(sub.indexof('@') + 1);
        // remove local parts, e.g. http://test.com/bla
        if (sub.indexof('/') != -1)
        {
            sub = sub.substring(0, sub.indexof('/'));
        }
        return sub;
    }

    /**
     * checks if the given generalname is in the permitted set.
     *
     * @param name the generalname
     * @throws pkixnameconstraintvalidatorexception
     *          if the <code>name</code>
     */
    public void checkpermitted(generalname name)
        throws pkixnameconstraintvalidatorexception
    {
        switch (name.gettagno())
        {
            case 1:
                checkpermittedemail(permittedsubtreesemail,
                    extractnameasstring(name));
                break;
            case 2:
                checkpermitteddns(permittedsubtreesdns, deria5string.getinstance(
                    name.getname()).getstring());
                break;
            case 4:
                checkpermitteddn(asn1sequence.getinstance(name.getname()
                    .toasn1primitive()));
                break;
            case 6:
                checkpermitteduri(permittedsubtreesuri, deria5string.getinstance(
                    name.getname()).getstring());
                break;
            case 7:
                byte[] ip = asn1octetstring.getinstance(name.getname()).getoctets();

                checkpermittedip(permittedsubtreesip, ip);
        }
    }

    /**
     * check if the given generalname is contained in the excluded set.
     *
     * @param name the generalname.
     * @throws pkixnameconstraintvalidatorexception
     *          if the <code>name</code> is
     *          excluded.
     */
    public void checkexcluded(generalname name)
        throws pkixnameconstraintvalidatorexception
    {
        switch (name.gettagno())
        {
            case 1:
                checkexcludedemail(excludedsubtreesemail, extractnameasstring(name));
                break;
            case 2:
                checkexcludeddns(excludedsubtreesdns, deria5string.getinstance(
                    name.getname()).getstring());
                break;
            case 4:
                checkexcludeddn(asn1sequence.getinstance(name.getname()
                    .toasn1primitive()));
                break;
            case 6:
                checkexcludeduri(excludedsubtreesuri, deria5string.getinstance(
                    name.getname()).getstring());
                break;
            case 7:
                byte[] ip = asn1octetstring.getinstance(name.getname()).getoctets();

                checkexcludedip(excludedsubtreesip, ip);
        }
    }

    public void intersectpermittedsubtree(generalsubtree permitted)
    {
        intersectpermittedsubtree(new generalsubtree[] { permitted });
    }

    /**
     * updates the permitted set of these name constraints with the intersection
     * with the given subtree.
     *
     * @param permitted the permitted subtrees
     */

    public void intersectpermittedsubtree(generalsubtree[] permitted)
    {
        map subtreesmap = new hashmap();

        // group in sets in a map ordered by tag no.
        for (int i = 0; i != permitted.length; i++)
        {
            generalsubtree subtree = permitted[i];
            integer tagno = integers.valueof(subtree.getbase().gettagno());
            if (subtreesmap.get(tagno) == null)
            {
                subtreesmap.put(tagno, new hashset());
            }
            ((set)subtreesmap.get(tagno)).add(subtree);
        }

        for (iterator it = subtreesmap.entryset().iterator(); it.hasnext();)
        {
            map.entry entry = (map.entry)it.next();

            // go through all subtree groups
            switch (((integer)entry.getkey()).intvalue())
            {
                case 1:
                    permittedsubtreesemail = intersectemail(permittedsubtreesemail,
                        (set)entry.getvalue());
                    break;
                case 2:
                    permittedsubtreesdns = intersectdns(permittedsubtreesdns,
                        (set)entry.getvalue());
                    break;
                case 4:
                    permittedsubtreesdn = intersectdn(permittedsubtreesdn,
                        (set)entry.getvalue());
                    break;
                case 6:
                    permittedsubtreesuri = intersecturi(permittedsubtreesuri,
                        (set)entry.getvalue());
                    break;
                case 7:
                    permittedsubtreesip = intersectip(permittedsubtreesip,
                        (set)entry.getvalue());
            }
        }
    }

    private string extractnameasstring(generalname name)
    {
        return deria5string.getinstance(name.getname()).getstring();
    }

    public void intersectemptypermittedsubtree(int nametype)
    {
        switch (nametype)
        {
        case 1:
            permittedsubtreesemail = new hashset();
            break;
        case 2:
            permittedsubtreesdns = new hashset();
            break;
        case 4:
            permittedsubtreesdn = new hashset();
            break;
        case 6:
            permittedsubtreesuri = new hashset();
            break;
        case 7:
            permittedsubtreesip = new hashset();
        }
    }

    /**
     * adds a subtree to the excluded set of these name constraints.
     *
     * @param subtree a subtree with an excluded generalname.
     */
    public void addexcludedsubtree(generalsubtree subtree)
    {
        generalname base = subtree.getbase();

        switch (base.gettagno())
        {
            case 1:
                excludedsubtreesemail = unionemail(excludedsubtreesemail,
                    extractnameasstring(base));
                break;
            case 2:
                excludedsubtreesdns = uniondns(excludedsubtreesdns,
                    extractnameasstring(base));
                break;
            case 4:
                excludedsubtreesdn = uniondn(excludedsubtreesdn,
                    (asn1sequence)base.getname().toasn1primitive());
                break;
            case 6:
                excludedsubtreesuri = unionuri(excludedsubtreesuri,
                    extractnameasstring(base));
                break;
            case 7:
                excludedsubtreesip = unionip(excludedsubtreesip, asn1octetstring
                    .getinstance(base.getname()).getoctets());
                break;
        }
    }

    /**
     * returns the maximum ip address.
     *
     * @param ip1 the first ip address.
     * @param ip2 the second ip address.
     * @return the maximum ip address.
     */
    private static byte[] max(byte[] ip1, byte[] ip2)
    {
        for (int i = 0; i < ip1.length; i++)
        {
            if ((ip1[i] & 0xffff) > (ip2[i] & 0xffff))
            {
                return ip1;
            }
        }
        return ip2;
    }

    /**
     * returns the minimum ip address.
     *
     * @param ip1 the first ip address.
     * @param ip2 the second ip address.
     * @return the minimum ip address.
     */
    private static byte[] min(byte[] ip1, byte[] ip2)
    {
        for (int i = 0; i < ip1.length; i++)
        {
            if ((ip1[i] & 0xffff) < (ip2[i] & 0xffff))
            {
                return ip1;
            }
        }
        return ip2;
    }

    /**
     * compares ip address <code>ip1</code> with <code>ip2</code>. if ip1
     * is equal to ip2 0 is returned. if ip1 is bigger 1 is returned, -1
     * otherwise.
     *
     * @param ip1 the first ip address.
     * @param ip2 the second ip address.
     * @return 0 if ip1 is equal to ip2, 1 if ip1 is bigger, -1 otherwise.
     */
    private static int compareto(byte[] ip1, byte[] ip2)
    {
        if (arrays.areequal(ip1, ip2))
        {
            return 0;
        }
        if (arrays.areequal(max(ip1, ip2), ip1))
        {
            return 1;
        }
        return -1;
    }

    /**
     * returns the logical or of the ip addresses <code>ip1</code> and
     * <code>ip2</code>.
     *
     * @param ip1 the first ip address.
     * @param ip2 the second ip address.
     * @return the or of <code>ip1</code> and <code>ip2</code>.
     */
    private static byte[] or(byte[] ip1, byte[] ip2)
    {
        byte[] temp = new byte[ip1.length];
        for (int i = 0; i < ip1.length; i++)
        {
            temp[i] = (byte)(ip1[i] | ip2[i]);
        }
        return temp;
    }

    public int hashcode()
    {
        return hashcollection(excludedsubtreesdn)
            + hashcollection(excludedsubtreesdns)
            + hashcollection(excludedsubtreesemail)
            + hashcollection(excludedsubtreesip)
            + hashcollection(excludedsubtreesuri)
            + hashcollection(permittedsubtreesdn)
            + hashcollection(permittedsubtreesdns)
            + hashcollection(permittedsubtreesemail)
            + hashcollection(permittedsubtreesip)
            + hashcollection(permittedsubtreesuri);
    }

    private int hashcollection(collection coll)
    {
        if (coll == null)
        {
            return 0;
        }
        int hash = 0;
        iterator it1 = coll.iterator();
        while (it1.hasnext())
        {
            object o = it1.next();
            if (o instanceof byte[])
            {
                hash += arrays.hashcode((byte[])o);
            }
            else
            {
                hash += o.hashcode();
            }
        }
        return hash;
    }

    public boolean equals(object o)
    {
        if (!(o instanceof pkixnameconstraintvalidator))
        {
            return false;
        }
        pkixnameconstraintvalidator constraintvalidator = (pkixnameconstraintvalidator)o;
        return collectionsareequal(constraintvalidator.excludedsubtreesdn, excludedsubtreesdn)
            && collectionsareequal(constraintvalidator.excludedsubtreesdns, excludedsubtreesdns)
            && collectionsareequal(constraintvalidator.excludedsubtreesemail, excludedsubtreesemail)
            && collectionsareequal(constraintvalidator.excludedsubtreesip, excludedsubtreesip)
            && collectionsareequal(constraintvalidator.excludedsubtreesuri, excludedsubtreesuri)
            && collectionsareequal(constraintvalidator.permittedsubtreesdn, permittedsubtreesdn)
            && collectionsareequal(constraintvalidator.permittedsubtreesdns, permittedsubtreesdns)
            && collectionsareequal(constraintvalidator.permittedsubtreesemail, permittedsubtreesemail)
            && collectionsareequal(constraintvalidator.permittedsubtreesip, permittedsubtreesip)
            && collectionsareequal(constraintvalidator.permittedsubtreesuri, permittedsubtreesuri);
    }

    private boolean collectionsareequal(collection coll1, collection coll2)
    {
        if (coll1 == coll2)
        {
            return true;
        }
        if (coll1 == null || coll2 == null)
        {
            return false;
        }
        if (coll1.size() != coll2.size())
        {
            return false;
        }
        iterator it1 = coll1.iterator();

        while (it1.hasnext())
        {
            object a = it1.next();
            iterator it2 = coll2.iterator();
            boolean found = false;
            while (it2.hasnext())
            {
                object b = it2.next();
                if (equals(a, b))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return false;
            }
        }
        return true;
    }

    private boolean equals(object o1, object o2)
    {
        if (o1 == o2)
        {
            return true;
        }
        if (o1 == null || o2 == null)
        {
            return false;
        }
        if (o1 instanceof byte[] && o2 instanceof byte[])
        {
            return arrays.areequal((byte[])o1, (byte[])o2);
        }
        else
        {
            return o1.equals(o2);
        }
    }

    /**
     * stringifies an ipv4 or v6 address with subnet mask.
     *
     * @param ip the ip with subnet mask.
     * @return the stringified ip address.
     */
    private string stringifyip(byte[] ip)
    {
        string temp = "";
        for (int i = 0; i < ip.length / 2; i++)
        {
            temp += integer.tostring(ip[i] & 0x00ff) + ".";
        }
        temp = temp.substring(0, temp.length() - 1);
        temp += "/";
        for (int i = ip.length / 2; i < ip.length; i++)
        {
            temp += integer.tostring(ip[i] & 0x00ff) + ".";
        }
        temp = temp.substring(0, temp.length() - 1);
        return temp;
    }

    private string stringifyipcollection(set ips)
    {
        string temp = "";
        temp += "[";
        for (iterator it = ips.iterator(); it.hasnext();)
        {
            temp += stringifyip((byte[])it.next()) + ",";
        }
        if (temp.length() > 1)
        {
            temp = temp.substring(0, temp.length() - 1);
        }
        temp += "]";
        return temp;
    }

    public string tostring()
    {
        string temp = "";
        temp += "permitted:\n";
        if (permittedsubtreesdn != null)
        {
            temp += "dn:\n";
            temp += permittedsubtreesdn.tostring() + "\n";
        }
        if (permittedsubtreesdns != null)
        {
            temp += "dns:\n";
            temp += permittedsubtreesdns.tostring() + "\n";
        }
        if (permittedsubtreesemail != null)
        {
            temp += "email:\n";
            temp += permittedsubtreesemail.tostring() + "\n";
        }
        if (permittedsubtreesuri != null)
        {
            temp += "uri:\n";
            temp += permittedsubtreesuri.tostring() + "\n";
        }
        if (permittedsubtreesip != null)
        {
            temp += "ip:\n";
            temp += stringifyipcollection(permittedsubtreesip) + "\n";
        }
        temp += "excluded:\n";
        if (!excludedsubtreesdn.isempty())
        {
            temp += "dn:\n";
            temp += excludedsubtreesdn.tostring() + "\n";
        }
        if (!excludedsubtreesdns.isempty())
        {
            temp += "dns:\n";
            temp += excludedsubtreesdns.tostring() + "\n";
        }
        if (!excludedsubtreesemail.isempty())
        {
            temp += "email:\n";
            temp += excludedsubtreesemail.tostring() + "\n";
        }
        if (!excludedsubtreesuri.isempty())
        {
            temp += "uri:\n";
            temp += excludedsubtreesuri.tostring() + "\n";
        }
        if (!excludedsubtreesip.isempty())
        {
            temp += "ip:\n";
            temp += stringifyipcollection(excludedsubtreesip) + "\n";
        }
        return temp;
    }
}
