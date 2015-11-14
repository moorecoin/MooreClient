package org.ripple.bouncycastle.x509.util;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.security.principal;
import java.security.cert.certificateparsingexception;
import java.security.cert.x509crl;
import java.security.cert.x509certificate;
import java.sql.date;
import java.util.arraylist;
import java.util.collection;
import java.util.hashmap;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.map;
import java.util.properties;
import java.util.set;

import javax.naming.context;
import javax.naming.namingenumeration;
import javax.naming.namingexception;
import javax.naming.directory.attribute;
import javax.naming.directory.dircontext;
import javax.naming.directory.initialdircontext;
import javax.naming.directory.searchcontrols;
import javax.naming.directory.searchresult;
import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.x509.certificate;
import org.ripple.bouncycastle.asn1.x509.certificatepair;
import org.ripple.bouncycastle.jce.x509ldapcertstoreparameters;
import org.ripple.bouncycastle.jce.provider.x509attrcertparser;
import org.ripple.bouncycastle.jce.provider.x509crlparser;
import org.ripple.bouncycastle.jce.provider.x509certpairparser;
import org.ripple.bouncycastle.jce.provider.x509certparser;
import org.ripple.bouncycastle.util.storeexception;
import org.ripple.bouncycastle.x509.x509attributecertstoreselector;
import org.ripple.bouncycastle.x509.x509attributecertificate;
import org.ripple.bouncycastle.x509.x509crlstoreselector;
import org.ripple.bouncycastle.x509.x509certpairstoreselector;
import org.ripple.bouncycastle.x509.x509certstoreselector;
import org.ripple.bouncycastle.x509.x509certificatepair;

/**
 * this is a general purpose implementation to get x.509 certificates, crls,
 * attribute certificates and cross certificates from a ldap location.
 * <p/>
 * at first a search is performed in the ldap*attributenames of the
 * {@link org.ripple.bouncycastle.jce.x509ldapcertstoreparameters} with the given
 * information of the subject (for all kind of certificates) or issuer (for
 * crls), respectively, if a {@link org.ripple.bouncycastle.x509.x509certstoreselector} or
 * {@link org.ripple.bouncycastle.x509.x509attributecertificate} is given with that
 * details.
 * <p/>
 * for the used schemes see:
 * <ul>
 * <li><a href="http://www.ietf.org/rfc/rfc2587.txt">rfc 2587</a>
 * <li><a
 * href="http://www3.ietf.org/proceedings/01mar/i-d/pkix-ldap-schema-01.txt">internet
 * x.509 public key infrastructure additional ldap schema for pkis and pmis</a>
 * </ul>
 */
public class ldapstorehelper
{

    // todo: cache results

    private x509ldapcertstoreparameters params;

    public ldapstorehelper(x509ldapcertstoreparameters params)
    {
        this.params = params;
    }

    /**
     * initial context factory.
     */
    private static string ldap_provider = "com.sun.jndi.ldap.ldapctxfactory";

    /**
     * processing referrals..
     */
    private static string referrals_ignore = "ignore";

    /**
     * security level to be used for ldap connections.
     */
    private static final string search_security_level = "none";

    /**
     * package prefix for loading url context factories.
     */
    private static final string url_context_prefix = "com.sun.jndi.url";

    private dircontext connectldap() throws namingexception
    {
        properties props = new properties();
        props.setproperty(context.initial_context_factory, ldap_provider);
        props.setproperty(context.batchsize, "0");

        props.setproperty(context.provider_url, params.getldapurl());
        props.setproperty(context.url_pkg_prefixes, url_context_prefix);
        props.setproperty(context.referral, referrals_ignore);
        props.setproperty(context.security_authentication,
            search_security_level);

        dircontext ctx = new initialdircontext(props);
        return ctx;
    }

    private string parsedn(string subject, string dnattributename)
    {
        string temp = subject;
        int begin = temp.tolowercase().indexof(
            dnattributename.tolowercase() + "=");
        if (begin == -1)
        {
            return "";
        }
        temp = temp.substring(begin + dnattributename.length());
        int end = temp.indexof(',');
        if (end == -1)
        {
            end = temp.length();
        }
        while (temp.charat(end - 1) == '\\')
        {
            end = temp.indexof(',', end + 1);
            if (end == -1)
            {
                end = temp.length();
            }
        }
        temp = temp.substring(0, end);
        begin = temp.indexof('=');
        temp = temp.substring(begin + 1);
        if (temp.charat(0) == ' ')
        {
            temp = temp.substring(1);
        }
        if (temp.startswith("\""))
        {
            temp = temp.substring(1);
        }
        if (temp.endswith("\""))
        {
            temp = temp.substring(0, temp.length() - 1);
        }
        return temp;
    }

    private set createcerts(list list, x509certstoreselector xselector)
        throws storeexception
    {
        set certset = new hashset();

        iterator it = list.iterator();
        x509certparser parser = new x509certparser();
        while (it.hasnext())
        {
            try
            {
                parser.engineinit(new bytearrayinputstream((byte[])it
                    .next()));
                x509certificate cert = (x509certificate)parser
                    .engineread();
                if (xselector.match((object)cert))
                {
                    certset.add(cert);
                }

            }
            catch (exception e)
            {

            }
        }

        return certset;
    }

    /**
     * can use the subject and serial and the subject and serialnumber of the
     * certificate of the given of the x509certstoreselector. if a certificate
     * for checking is given this has higher precedence.
     *
     * @param xselector             the selector with the search criteria.
     * @param attrs                 attributes which contain the certificates in the ldap
     *                              directory.
     * @param attrnames             attribute names in teh ldap directory which correspond to the
     *                              subjectattributenames.
     * @param subjectattributenames subject attribute names (like "cn", "o", "ou") to use to
     *                              search in the ldap directory
     * @return a list of found der encoded certificates.
     * @throws storeexception if an error occurs while searching.
     */
    private list certsubjectserialsearch(x509certstoreselector xselector,
                                         string[] attrs, string attrnames[], string subjectattributenames[])
        throws storeexception
    {
        // todo: support also subjectaltnames?
        list list = new arraylist();

        string subject = null;
        string serial = null;

        subject = getsubjectasstring(xselector);

        if (xselector.getserialnumber() != null)
        {
            serial = xselector.getserialnumber().tostring();
        }
        if (xselector.getcertificate() != null)
        {
            subject = xselector.getcertificate().getsubjectx500principal().getname("rfc1779");
            serial = xselector.getcertificate().getserialnumber().tostring();
        }

        string attrvalue = null;
        if (subject != null)
        {
            for (int i = 0; i < subjectattributenames.length; i++)
            {
                attrvalue = parsedn(subject, subjectattributenames[i]);
                list
                    .addall(search(attrnames, "*" + attrvalue + "*",
                        attrs));
            }
        }
        if (serial != null && params.getsearchforserialnumberin() != null)
        {
            attrvalue = serial;
            list.addall(search(
                splitstring(params.getsearchforserialnumberin()),
                                                  attrvalue, attrs));
        }
        if (serial == null && subject == null)
        {
            list.addall(search(attrnames, "*", attrs));
        }

        return list;
    }



    /**
     * can use the subject of the forward certificate of the set certificate
     * pair or the subject of the forward
     * {@link org.ripple.bouncycastle.x509.x509certstoreselector} of the given
     * selector.
     *
     * @param xselector             the selector with the search criteria.
     * @param attrs                 attributes which contain the attribute certificates in the
     *                              ldap directory.
     * @param attrnames             attribute names in the ldap directory which correspond to the
     *                              subjectattributenames.
     * @param subjectattributenames subject attribute names (like "cn", "o", "ou") to use to
     *                              search in the ldap directory
     * @return a list of found der encoded certificate pairs.
     * @throws storeexception if an error occurs while searching.
     */
    private list crosscertificatepairsubjectsearch(
        x509certpairstoreselector xselector, string[] attrs,
        string attrnames[], string subjectattributenames[])
        throws storeexception
    {
        list list = new arraylist();

        // search for subject
        string subject = null;

        if (xselector.getforwardselector() != null)
        {
            subject = getsubjectasstring(xselector.getforwardselector());
        }
        if (xselector.getcertpair() != null)
        {
            if (xselector.getcertpair().getforward() != null)
            {
                subject = xselector.getcertpair().getforward()
                    .getsubjectx500principal().getname("rfc1779");
            }
        }
        string attrvalue = null;
        if (subject != null)
        {
            for (int i = 0; i < subjectattributenames.length; i++)
            {
                attrvalue = parsedn(subject, subjectattributenames[i]);
                list
                    .addall(search(attrnames, "*" + attrvalue + "*",
                        attrs));
            }
        }
        if (subject == null)
        {
            list.addall(search(attrnames, "*", attrs));
        }

        return list;
    }

    /**
     * can use the entityname of the holder of the attribute certificate, the
     * serialnumber of attribute certificate and the serialnumber of the
     * associated certificate of the given of the x509attributecertselector.
     *
     * @param xselector             the selector with the search criteria.
     * @param attrs                 attributes which contain the attribute certificates in the
     *                              ldap directory.
     * @param attrnames             attribute names in the ldap directory which correspond to the
     *                              subjectattributenames.
     * @param subjectattributenames subject attribute names (like "cn", "o", "ou") to use to
     *                              search in the ldap directory
     * @return a list of found der encoded attribute certificates.
     * @throws storeexception if an error occurs while searching.
     */
    private list attrcertsubjectserialsearch(
        x509attributecertstoreselector xselector, string[] attrs,
        string attrnames[], string subjectattributenames[])
        throws storeexception
    {
        list list = new arraylist();

        // search for serialnumber of associated cert,
        // serialnumber of the attribute certificate or dn in the entityname
        // of the holder

        string subject = null;
        string serial = null;

        collection serials = new hashset();
        principal principals[] = null;
        if (xselector.getholder() != null)
        {
            // serialnumber of associated cert
            if (xselector.getholder().getserialnumber() != null)
            {
                serials.add(xselector.getholder().getserialnumber()
                    .tostring());
            }
            // dn in the entityname of the holder
            if (xselector.getholder().getentitynames() != null)
            {
                principals = xselector.getholder().getentitynames();
            }
        }

        if (xselector.getattributecert() != null)
        {
            if (xselector.getattributecert().getholder().getentitynames() != null)
            {
                principals = xselector.getattributecert().getholder()
                    .getentitynames();
            }
            // serialnumber of the attribute certificate
            serials.add(xselector.getattributecert().getserialnumber()
                .tostring());
        }
        if (principals != null)
        {
            // only first should be relevant
            if (principals[0] instanceof x500principal)
            {
                subject = ((x500principal)principals[0])
                    .getname("rfc1779");
            }
            else
            {
                // strange ...
                subject = principals[0].getname();
            }
        }
        if (xselector.getserialnumber() != null)
        {
            serials.add(xselector.getserialnumber().tostring());
        }

        string attrvalue = null;
        if (subject != null)
        {
            for (int i = 0; i < subjectattributenames.length; i++)
            {
                attrvalue = parsedn(subject, subjectattributenames[i]);
                list
                    .addall(search(attrnames, "*" + attrvalue + "*",
                        attrs));
            }
        }
        if (serials.size() > 0
            && params.getsearchforserialnumberin() != null)
        {
            iterator it = serials.iterator();
            while (it.hasnext())
            {
                serial = (string)it.next();
                list.addall(search(splitstring(params.getsearchforserialnumberin()), serial, attrs));
            }
        }
        if (serials.size() == 0 && subject == null)
        {
            list.addall(search(attrnames, "*", attrs));
        }

        return list;
    }

    /**
     * can use the issuer of the given of the x509crlstoreselector.
     *
     * @param xselector            the selector with the search criteria.
     * @param attrs                attributes which contain the attribute certificates in the
     *                             ldap directory.
     * @param attrnames            attribute names in the ldap directory which correspond to the
     *                             subjectattributenames.
     * @param issuerattributenames issuer attribute names (like "cn", "o", "ou") to use to search
     *                             in the ldap directory
     * @return a list of found der encoded crls.
     * @throws storeexception if an error occurs while searching.
     */
    private list crlissuersearch(x509crlstoreselector xselector,
                                 string[] attrs, string attrnames[], string issuerattributenames[])
        throws storeexception
    {
        list list = new arraylist();

        string issuer = null;
        collection issuers = new hashset();
        if (xselector.getissuers() != null)
        {
            issuers.addall(xselector.getissuers());
        }
        if (xselector.getcertificatechecking() != null)
        {
            issuers.add(getcertificateissuer(xselector.getcertificatechecking()));
        }
        if (xselector.getattrcertificatechecking() != null)
        {
            principal principals[] = xselector.getattrcertificatechecking().getissuer().getprincipals();
            for (int i=0; i<principals.length; i++)
            {
                if (principals[i] instanceof x500principal)
                {
                    issuers.add(principals[i]);        
                }
            }
        }
        iterator it = issuers.iterator();
        while (it.hasnext())
        {
            issuer = ((x500principal)it.next()).getname("rfc1779");
            string attrvalue = null;

            for (int i = 0; i < issuerattributenames.length; i++)
            {
                attrvalue = parsedn(issuer, issuerattributenames[i]);
                list
                    .addall(search(attrnames, "*" + attrvalue + "*",
                        attrs));
            }
        }
        if (issuer == null)
        {
            list.addall(search(attrnames, "*", attrs));
        }

        return list;
    }

    /**
     * returns a <code>list</code> of encodings of the certificates, attribute
     * certificates, crl or certificate pairs.
     *
     * @param attributenames the attribute names to look for in the ldap.
     * @param attributevalue the value the attribute name must have.
     * @param attrs          the attributes in the ldap which hold the certificate,
     *                       attribute certificate, certificate pair or crl in a found
     *                       entry.
     * @return a <code>list</code> of byte arrays with the encodings.
     * @throws storeexception if an error occurs getting the results from the ldap
     *                        directory.
     */
    private list search(string attributenames[], string attributevalue,
                        string[] attrs) throws storeexception
    {
        string filter = null;
        if (attributenames == null)
        {
            filter = null;
        }
        else
        {
            filter = "";
            if (attributevalue.equals("**"))
            {
                attributevalue = "*";
            }
            for (int i = 0; i < attributenames.length; i++)
            {
                filter += "(" + attributenames[i] + "=" + attributevalue + ")";
            }
            filter = "(|" + filter + ")";
        }
        string filter2 = "";
        for (int i = 0; i < attrs.length; i++)
        {
            filter2 += "(" + attrs[i] + "=*)";
        }
        filter2 = "(|" + filter2 + ")";

        string filter3 = "(&" + filter + "" + filter2 + ")";
        if (filter == null)
        {
            filter3 = filter2;
        }
        list list;
        list = getfromcache(filter3);
        if (list != null)
        {
            return list;
        }
        dircontext ctx = null;
        list = new arraylist();
        try
        {

            ctx = connectldap();

            searchcontrols constraints = new searchcontrols();
            constraints.setsearchscope(searchcontrols.subtree_scope);
            constraints.setcountlimit(0);
            constraints.setreturningattributes(attrs);
            namingenumeration results = ctx.search(params.getbasedn(), filter3,
                constraints);
            while (results.hasmoreelements())
            {
                searchresult sr = (searchresult)results.next();
                namingenumeration enumeration = ((attribute)(sr
                    .getattributes().getall().next())).getall();
                while (enumeration.hasmore())
                {
                    list.add(enumeration.next());
                }
            }
            addtocache(filter3, list);
        }
        catch (namingexception e)
        {
            // skip exception, unfortunately if an attribute type is not
            // supported an exception is thrown

        }
        finally
        {
            try
            {
                if (null != ctx)
                {
                    ctx.close();
                }
            }
            catch (exception e)
            {
            }
        }
        return list;
    }

    private set createcrls(list list, x509crlstoreselector xselector)
        throws storeexception
    {
        set crlset = new hashset();

        x509crlparser parser = new x509crlparser();
        iterator it = list.iterator();
        while (it.hasnext())
        {
            try
            {
                parser.engineinit(new bytearrayinputstream((byte[])it
                    .next()));
                x509crl crl = (x509crl)parser.engineread();
                if (xselector.match((object)crl))
                {
                    crlset.add(crl);
                }
            }
            catch (streamparsingexception e)
            {

            }
        }

        return crlset;
    }

    private set createcrosscertificatepairs(list list,
                                            x509certpairstoreselector xselector) throws storeexception
    {
        set certpairset = new hashset();

        int i = 0;
        while (i < list.size())
        {
            x509certificatepair pair;
            try
            {
                // first try to decode it as certificate pair
                try
                {
                    x509certpairparser parser = new x509certpairparser();
                    parser.engineinit(new bytearrayinputstream(
                        (byte[])list.get(i)));
                    pair = (x509certificatepair)parser.engineread();
                }
                catch (streamparsingexception e)
                {
                    // now try it to construct it the forward and reverse
                    // certificate
                    byte[] forward = (byte[])list.get(i);
                    byte[] reverse = (byte[])list.get(i + 1);
                    pair = new x509certificatepair(new certificatepair(
                        certificate
                            .getinstance(new asn1inputstream(
                            forward).readobject()),
                        certificate
                            .getinstance(new asn1inputstream(
                                reverse).readobject())));
                    i++;
                }
                if (xselector.match((object)pair))
                {
                    certpairset.add(pair);
                }
            }
            catch (certificateparsingexception e)
            {
                // try next
            }
            catch (ioexception e)
            {
                // try next
            }
            i++;
        }

        return certpairset;
    }

    private set createattributecertificates(list list,
                                            x509attributecertstoreselector xselector) throws storeexception
    {
        set certset = new hashset();

        iterator it = list.iterator();
        x509attrcertparser parser = new x509attrcertparser();
        while (it.hasnext())
        {
            try
            {
                parser.engineinit(new bytearrayinputstream((byte[])it
                    .next()));
                x509attributecertificate cert = (x509attributecertificate)parser
                    .engineread();
                if (xselector.match((object)cert))
                {
                    certset.add(cert);
                }
            }
            catch (streamparsingexception e)
            {

            }
        }

        return certset;
    }

    /**
     * returns the crls for issued certificates for other cas matching the given
     * selector. <br>
     * the authorityrevocationlist attribute includes revocation information
     * regarding certificates issued to other cas.
     *
     * @param selector the crl selector to use to find the crls.
     * @return a possible empty collection with crls
     * @throws storeexception
     */
    public collection getauthorityrevocationlists(x509crlstoreselector selector)
        throws storeexception
    {
        string[] attrs = splitstring(params.getauthorityrevocationlistattribute());
        string attrnames[] = splitstring(params
            .getldapauthorityrevocationlistattributename());
        string issuerattributenames[] = splitstring(params
            .getauthorityrevocationlistissuerattributename());

        list list = crlissuersearch(selector, attrs, attrnames,
            issuerattributenames);
        set resultset = createcrls(list, selector);
        if (resultset.size() == 0)
        {
            x509crlstoreselector emptyselector = new x509crlstoreselector();
            list = crlissuersearch(emptyselector, attrs, attrnames,
                issuerattributenames);

            resultset.addall(createcrls(list, selector));
        }
        return resultset;
    }

    /**
     * returns the revocation list for revoked attribute certificates.
     * <p/>
     * the attributecertificaterevocationlist holds a list of attribute
     * certificates that have been revoked.
     *
     * @param selector the crl selector to use to find the crls.
     * @return a possible empty collection with crls.
     * @throws storeexception
     */
    public collection getattributecertificaterevocationlists(
        x509crlstoreselector selector) throws storeexception
    {
        string[] attrs = splitstring(params
            .getattributecertificaterevocationlistattribute());
        string attrnames[] = splitstring(params
            .getldapattributecertificaterevocationlistattributename());
        string issuerattributenames[] = splitstring(params
            .getattributecertificaterevocationlistissuerattributename());

        list list = crlissuersearch(selector, attrs, attrnames,
            issuerattributenames);
        set resultset = createcrls(list, selector);
        if (resultset.size() == 0)
        {
            x509crlstoreselector emptyselector = new x509crlstoreselector();
            list = crlissuersearch(emptyselector, attrs, attrnames,
                issuerattributenames);

            resultset.addall(createcrls(list, selector));
        }
        return resultset;
    }

    /**
     * returns the revocation list for revoked attribute certificates for an
     * attribute authority
     * <p/>
     * the attributeauthoritylist holds a list of aa certificates that have been
     * revoked.
     *
     * @param selector the crl selector to use to find the crls.
     * @return a possible empty collection with crls
     * @throws storeexception
     */
    public collection getattributeauthorityrevocationlists(
        x509crlstoreselector selector) throws storeexception
    {
        string[] attrs = splitstring(params.getattributeauthorityrevocationlistattribute());
        string attrnames[] = splitstring(params
            .getldapattributeauthorityrevocationlistattributename());
        string issuerattributenames[] = splitstring(params
            .getattributeauthorityrevocationlistissuerattributename());

        list list = crlissuersearch(selector, attrs, attrnames,
            issuerattributenames);
        set resultset = createcrls(list, selector);
        if (resultset.size() == 0)
        {
            x509crlstoreselector emptyselector = new x509crlstoreselector();
            list = crlissuersearch(emptyselector, attrs, attrnames,
                issuerattributenames);

            resultset.addall(createcrls(list, selector));
        }
        return resultset;
    }

    /**
     * returns cross certificate pairs.
     *
     * @param selector the selector to use to find the cross certificates.
     * @return a possible empty collection with {@link x509certificatepair}s
     * @throws storeexception
     */
    public collection getcrosscertificatepairs(
        x509certpairstoreselector selector) throws storeexception
    {
        string[] attrs = splitstring(params.getcrosscertificateattribute());
        string attrnames[] = splitstring(params.getldapcrosscertificateattributename());
        string subjectattributenames[] = splitstring(params
            .getcrosscertificatesubjectattributename());
        list list = crosscertificatepairsubjectsearch(selector, attrs,
            attrnames, subjectattributenames);
        set resultset = createcrosscertificatepairs(list, selector);
        if (resultset.size() == 0)
        {
            x509certstoreselector emptycertselector = new x509certstoreselector();
            x509certpairstoreselector emptyselector = new x509certpairstoreselector();

            emptyselector.setforwardselector(emptycertselector);
            emptyselector.setreverseselector(emptycertselector);
            list = crosscertificatepairsubjectsearch(emptyselector, attrs,
                attrnames, subjectattributenames);
            resultset.addall(createcrosscertificatepairs(list, selector));
        }
        return resultset;
    }

    /**
     * returns end certificates.
     * <p/>
     * the attributedescriptorcertificate is self signed by a source of
     * authority and holds a description of the privilege and its delegation
     * rules.
     *
     * @param selector the selector to find the certificates.
     * @return a possible empty collection with certificates.
     * @throws storeexception
     */
    public collection getusercertificates(x509certstoreselector selector)
        throws storeexception
    {
        string[] attrs = splitstring(params.getusercertificateattribute());
        string attrnames[] = splitstring(params.getldapusercertificateattributename());
        string subjectattributenames[] = splitstring(params
            .getusercertificatesubjectattributename());

        list list = certsubjectserialsearch(selector, attrs, attrnames,
            subjectattributenames);
        set resultset = createcerts(list, selector);
        if (resultset.size() == 0)
        {
            x509certstoreselector emptyselector = new x509certstoreselector();
            list = certsubjectserialsearch(emptyselector, attrs, attrnames,
                subjectattributenames);
            resultset.addall(createcerts(list, selector));
        }

        return resultset;
    }

    /**
     * returns attribute certificates for an attribute authority
     * <p/>
     * the aacertificate holds the privileges of an attribute authority.
     *
     * @param selector the selector to find the attribute certificates.
     * @return a possible empty collection with attribute certificates.
     * @throws storeexception
     */
    public collection getaacertificates(x509attributecertstoreselector selector)
        throws storeexception
    {
        string[] attrs = splitstring(params.getaacertificateattribute());
        string attrnames[] = splitstring(params.getldapaacertificateattributename());
        string subjectattributenames[] = splitstring(params.getaacertificatesubjectattributename());

        list list = attrcertsubjectserialsearch(selector, attrs, attrnames,
            subjectattributenames);
        set resultset = createattributecertificates(list, selector);
        if (resultset.size() == 0)
        {
            x509attributecertstoreselector emptyselector = new x509attributecertstoreselector();
            list = attrcertsubjectserialsearch(emptyselector, attrs, attrnames,
                subjectattributenames);
            resultset.addall(createattributecertificates(list, selector));
        }

        return resultset;
    }

    /**
     * returns an attribute certificate for an authority
     * <p/>
     * the attributedescriptorcertificate is self signed by a source of
     * authority and holds a description of the privilege and its delegation
     * rules.
     *
     * @param selector the selector to find the attribute certificates.
     * @return a possible empty collection with attribute certificates.
     * @throws storeexception
     */
    public collection getattributedescriptorcertificates(
        x509attributecertstoreselector selector) throws storeexception
    {
        string[] attrs = splitstring(params.getattributedescriptorcertificateattribute());
        string attrnames[] = splitstring(params
            .getldapattributedescriptorcertificateattributename());
        string subjectattributenames[] = splitstring(params
            .getattributedescriptorcertificatesubjectattributename());

        list list = attrcertsubjectserialsearch(selector, attrs, attrnames,
            subjectattributenames);
        set resultset = createattributecertificates(list, selector);
        if (resultset.size() == 0)
        {
            x509attributecertstoreselector emptyselector = new x509attributecertstoreselector();
            list = attrcertsubjectserialsearch(emptyselector, attrs, attrnames,
                subjectattributenames);
            resultset.addall(createattributecertificates(list, selector));
        }

        return resultset;
    }

    /**
     * returns ca certificates.
     * <p/>
     * the cacertificate attribute of a ca's directory entry shall be used to
     * store self-issued certificates (if any) and certificates issued to this
     * ca by cas in the same realm as this ca.
     *
     * @param selector the selector to find the certificates.
     * @return a possible empty collection with certificates.
     * @throws storeexception
     */
    public collection getcacertificates(x509certstoreselector selector)
        throws storeexception
    {
        string[] attrs = splitstring(params.getcacertificateattribute());
        string attrnames[] = splitstring(params.getldapcacertificateattributename());
        string subjectattributenames[] = splitstring(params
            .getcacertificatesubjectattributename());
        list list = certsubjectserialsearch(selector, attrs, attrnames,
            subjectattributenames);
        set resultset = createcerts(list, selector);
        if (resultset.size() == 0)
        {
            x509certstoreselector emptyselector = new x509certstoreselector();
            list = certsubjectserialsearch(emptyselector, attrs, attrnames,
                subjectattributenames);
            resultset.addall(createcerts(list, selector));
        }
        return resultset;
    }

    /**
     * returns the delta revocation list for revoked certificates.
     *
     * @param selector the crl selector to use to find the crls.
     * @return a possible empty collection with crls.
     * @throws storeexception
     */
    public collection getdeltacertificaterevocationlists(
        x509crlstoreselector selector) throws storeexception
    {
        string[] attrs = splitstring(params.getdeltarevocationlistattribute());
        string attrnames[] = splitstring(params.getldapdeltarevocationlistattributename());
        string issuerattributenames[] = splitstring(params
            .getdeltarevocationlistissuerattributename());
        list list = crlissuersearch(selector, attrs, attrnames,
            issuerattributenames);
        set resultset = createcrls(list, selector);
        if (resultset.size() == 0)
        {
            x509crlstoreselector emptyselector = new x509crlstoreselector();
            list = crlissuersearch(emptyselector, attrs, attrnames,
                issuerattributenames);

            resultset.addall(createcrls(list, selector));
        }
        return resultset;
    }

    /**
     * returns an attribute certificate for an user.
     * <p/>
     * the attributecertificateattribute holds the privileges of a user
     *
     * @param selector the selector to find the attribute certificates.
     * @return a possible empty collection with attribute certificates.
     * @throws storeexception
     */
    public collection getattributecertificateattributes(
        x509attributecertstoreselector selector) throws storeexception
    {
        string[] attrs = splitstring(params.getattributecertificateattributeattribute());
        string attrnames[] = splitstring(params
            .getldapattributecertificateattributeattributename());
        string subjectattributenames[] = splitstring(params
            .getattributecertificateattributesubjectattributename());
        list list = attrcertsubjectserialsearch(selector, attrs, attrnames,
            subjectattributenames);
        set resultset = createattributecertificates(list, selector);
        if (resultset.size() == 0)
        {
            x509attributecertstoreselector emptyselector = new x509attributecertstoreselector();
            list = attrcertsubjectserialsearch(emptyselector, attrs, attrnames,
                subjectattributenames);
            resultset.addall(createattributecertificates(list, selector));
        }

        return resultset;
    }

    /**
     * returns the certificate revocation lists for revoked certificates.
     *
     * @param selector the crl selector to use to find the crls.
     * @return a possible empty collection with crls.
     * @throws storeexception
     */
    public collection getcertificaterevocationlists(
        x509crlstoreselector selector) throws storeexception
    {
        string[] attrs = splitstring(params.getcertificaterevocationlistattribute());
        string attrnames[] = splitstring(params
            .getldapcertificaterevocationlistattributename());
        string issuerattributenames[] = splitstring(params
            .getcertificaterevocationlistissuerattributename());
        list list = crlissuersearch(selector, attrs, attrnames,
            issuerattributenames);
        set resultset = createcrls(list, selector);
        if (resultset.size() == 0)
        {
            x509crlstoreselector emptyselector = new x509crlstoreselector();
            list = crlissuersearch(emptyselector, attrs, attrnames,
                issuerattributenames);

            resultset.addall(createcrls(list, selector));
        }
        return resultset;
    }

    private map cachemap = new hashmap(cachesize);

    private static int cachesize = 32;

    private static long lifetime = 60 * 1000;

    private synchronized void addtocache(string searchcriteria, list list)
    {
        date now = new date(system.currenttimemillis());
        list cacheentry = new arraylist();
        cacheentry.add(now);
        cacheentry.add(list);
        if (cachemap.containskey(searchcriteria))
        {
            cachemap.put(searchcriteria, cacheentry);
        }
        else
        {
            if (cachemap.size() >= cachesize)
            {
                // replace oldest
                iterator it = cachemap.entryset().iterator();
                long oldest = now.gettime();
                object replace = null;
                while (it.hasnext())
                {
                    map.entry entry = (map.entry)it.next();
                    long current = ((date)((list)entry.getvalue()).get(0))
                        .gettime();
                    if (current < oldest)
                    {
                        oldest = current;
                        replace = entry.getkey();
                    }
                }
                cachemap.remove(replace);
            }
            cachemap.put(searchcriteria, cacheentry);
        }
    }

    private list getfromcache(string searchcriteria)
    {
        list entry = (list)cachemap.get(searchcriteria);
        long now = system.currenttimemillis();
        if (entry != null)
        {
            // too old
            if (((date)entry.get(0)).gettime() < (now - lifetime))
            {
                return null;
            }
            return (list)entry.get(1);
        }
        return null;
    }

    /*
     * spilt string based on spaces
     */
    private string[] splitstring(string str)
    {
        return str.split("\\s+");
    }

    private string getsubjectasstring(x509certstoreselector xselector)
    {
        try
        {
            byte[] encsubject = xselector.getsubjectasbytes();
            if (encsubject != null)
            {
                return new x500principal(encsubject).getname("rfc1779");
            }
        }
        catch (ioexception e)
        {
            throw new storeexception("exception processing name: " + e.getmessage(), e);
        }
        return null;
    }

    private x500principal getcertificateissuer(x509certificate cert)
    {
        return cert.getissuerx500principal();
    }
}
