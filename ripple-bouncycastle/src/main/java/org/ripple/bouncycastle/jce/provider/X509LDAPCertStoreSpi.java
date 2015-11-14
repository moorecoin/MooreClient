package org.ripple.bouncycastle.jce.provider;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.security.invalidalgorithmparameterexception;
import java.security.cert.crl;
import java.security.cert.crlselector;
import java.security.cert.certselector;
import java.security.cert.certstoreexception;
import java.security.cert.certstoreparameters;
import java.security.cert.certstorespi;
import java.security.cert.certificate;
import java.security.cert.certificatefactory;
import java.security.cert.x509crlselector;
import java.security.cert.x509certselector;
import java.util.arraylist;
import java.util.collection;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
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
import org.ripple.bouncycastle.asn1.x509.certificatepair;
import org.ripple.bouncycastle.jce.x509ldapcertstoreparameters;

/**
 * 
 * this is a general purpose implementation to get x.509 certificates and crls
 * from a ldap location.
 * <p>
 * at first a search is performed in the ldap*attributenames of the
 * {@link org.ripple.bouncycastle.jce.x509ldapcertstoreparameters} with the given
 * information of the subject (for all kind of certificates) or issuer (for
 * crls), respectively, if a x509certselector is given with that details. for
 * crls, ca certificates and cross certificates a coarse search is made only for
 * entries with that content to get more possibly matchign results.
 */
public class x509ldapcertstorespi
    extends certstorespi
{
    private x509ldapcertstoreparameters params;

    public x509ldapcertstorespi(certstoreparameters params)
        throws invalidalgorithmparameterexception
    {
        super(params);

        if (!(params instanceof x509ldapcertstoreparameters))
        {
            throw new invalidalgorithmparameterexception(
                x509ldapcertstorespi.class.getname() + ": parameter must be a " + x509ldapcertstoreparameters.class.getname() + " object\n"
                    + params.tostring());
        }

        this.params = (x509ldapcertstoreparameters)params;
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

    private string parsedn(string subject, string subjectattributename)
    {
        string temp = subject;
        int begin = temp.tolowercase().indexof(
            subjectattributename.tolowercase());
        temp = temp.substring(begin + subjectattributename.length());
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

    public collection enginegetcertificates(certselector selector)
        throws certstoreexception
    {
        if (!(selector instanceof x509certselector))
        {
            throw new certstoreexception("selector is not a x509certselector");
        }
        x509certselector xselector = (x509certselector)selector;

        set certset = new hashset();

        set set = getendcertificates(xselector);
        set.addall(getcacertificates(xselector));
        set.addall(getcrosscertificates(xselector));

        iterator it = set.iterator();

        try
        {
            certificatefactory cf = certificatefactory.getinstance("x.509",
                bouncycastleprovider.provider_name);
            while (it.hasnext())
            {
                byte[] bytes = (byte[])it.next();
                if (bytes == null || bytes.length == 0)
                {
                    continue;
                }

                list byteslist = new arraylist();
                byteslist.add(bytes);

                try
                {
                    certificatepair pair = certificatepair
                        .getinstance(new asn1inputstream(bytes)
                            .readobject());
                    byteslist.clear();
                    if (pair.getforward() != null)
                    {
                        byteslist.add(pair.getforward().getencoded());
                    }
                    if (pair.getreverse() != null)
                    {
                        byteslist.add(pair.getreverse().getencoded());
                    }
                }
                catch (ioexception e)
                {

                }
                catch (illegalargumentexception e)
                {

                }
                for (iterator it2 = byteslist.iterator(); it2.hasnext();)
                {
                    bytearrayinputstream bin = new bytearrayinputstream(
                        (byte[])it2.next());
                    try
                    {
                        certificate cert = cf.generatecertificate(bin);
                        // system.out.println(((x509certificate)
                        // cert).getsubjectx500principal());
                        if (xselector.match(cert))
                        {
                            certset.add(cert);
                        }
                    }
                    catch (exception e)
                    {

                    }
                }
            }
        }
        catch (exception e)
        {
            throw new certstoreexception(
                "certificate cannot be constructed from ldap result: " + e);
        }

        return certset;
    }

    private set certsubjectserialsearch(x509certselector xselector,
                                        string[] attrs, string attrname, string subjectattributename)
        throws certstoreexception
    {
        set set = new hashset();
        try
        {
            if (xselector.getsubjectasbytes() != null
                || xselector.getsubjectasstring() != null
                || xselector.getcertificate() != null)
            {
                string subject = null;
                string serial = null;
                if (xselector.getcertificate() != null)
                {
                    subject = xselector.getcertificate()
                        .getsubjectx500principal().getname("rfc1779");
                    serial = xselector.getcertificate().getserialnumber()
                        .tostring();
                }
                else
                {
                    if (xselector.getsubjectasbytes() != null)
                    {
                        subject = new x500principal(xselector
                            .getsubjectasbytes()).getname("rfc1779");
                    }
                    else
                    {
                        subject = xselector.getsubjectasstring();
                    }
                }
                string attrvalue = parsedn(subject, subjectattributename);
                set.addall(search(attrname, "*" + attrvalue + "*", attrs));
                if (serial != null
                    && params.getsearchforserialnumberin() != null)
                {
                    attrvalue = serial;
                    attrname = params.getsearchforserialnumberin();
                    set.addall(search(attrname, "*" + attrvalue + "*", attrs));
                }
            }
            else
            {
                set.addall(search(attrname, "*", attrs));
            }
        }
        catch (ioexception e)
        {
            throw new certstoreexception("exception processing selector: " + e);
        }

        return set;
    }

    private set getendcertificates(x509certselector xselector)
        throws certstoreexception
    {
        string[] attrs = {params.getusercertificateattribute()};
        string attrname = params.getldapusercertificateattributename();
        string subjectattributename = params.getusercertificatesubjectattributename();

        set set = certsubjectserialsearch(xselector, attrs, attrname,
            subjectattributename);
        return set;
    }

    private set getcacertificates(x509certselector xselector)
        throws certstoreexception
    {
        string[] attrs = {params.getcacertificateattribute()};
        string attrname = params.getldapcacertificateattributename();
        string subjectattributename = params
            .getcacertificatesubjectattributename();
        set set = certsubjectserialsearch(xselector, attrs, attrname,
            subjectattributename);

        if (set.isempty())
        {
            set.addall(search(null, "*", attrs));
        }

        return set;
    }

    private set getcrosscertificates(x509certselector xselector)
        throws certstoreexception
    {
        string[] attrs = {params.getcrosscertificateattribute()};
        string attrname = params.getldapcrosscertificateattributename();
        string subjectattributename = params
            .getcrosscertificatesubjectattributename();
        set set = certsubjectserialsearch(xselector, attrs, attrname,
            subjectattributename);

        if (set.isempty())
        {
            set.addall(search(null, "*", attrs));
        }

        return set;
    }

    public collection enginegetcrls(crlselector selector)
        throws certstoreexception
    {
        string[] attrs = {params.getcertificaterevocationlistattribute()};
        if (!(selector instanceof x509crlselector))
        {
            throw new certstoreexception("selector is not a x509crlselector");
        }
        x509crlselector xselector = (x509crlselector)selector;

        set crlset = new hashset();

        string attrname = params.getldapcertificaterevocationlistattributename();
        set set = new hashset();

        if (xselector.getissuernames() != null)
        {
            for (iterator it = xselector.getissuernames().iterator(); it
                .hasnext();)
            {
                object o = it.next();
                string attrvalue = null;
                if (o instanceof string)
                {
                    string issuerattributename = params
                        .getcertificaterevocationlistissuerattributename();
                    attrvalue = parsedn((string)o, issuerattributename);
                }
                else
                {
                    string issuerattributename = params
                        .getcertificaterevocationlistissuerattributename();
                    attrvalue = parsedn(new x500principal((byte[])o)
                        .getname("rfc1779"), issuerattributename);
                }
                set.addall(search(attrname, "*" + attrvalue + "*", attrs));
            }
        }
        else
        {
            set.addall(search(attrname, "*", attrs));
        }
        set.addall(search(null, "*", attrs));
        iterator it = set.iterator();

        try
        {
            certificatefactory cf = certificatefactory.getinstance("x.509",
                bouncycastleprovider.provider_name);
            while (it.hasnext())
            {
                crl crl = cf.generatecrl(new bytearrayinputstream((byte[])it
                    .next()));
                if (xselector.match(crl))
                {
                    crlset.add(crl);
                }
            }
        }
        catch (exception e)
        {
            throw new certstoreexception(
                "crl cannot be constructed from ldap result " + e);
        }

        return crlset;
    }

    /**
     * returns a set of byte arrays with the certificate or crl encodings.
     *
     * @param attributename  the attribute name to look for in the ldap.
     * @param attributevalue the value the attribute name must have.
     * @param attrs          the attributes in the ldap which hold the certificate,
     *                       certificate pair or crl in a found entry.
     * @return set of byte arrays with the certificate encodings.
     */
    private set search(string attributename, string attributevalue,
                       string[] attrs) throws certstoreexception
    {
        string filter = attributename + "=" + attributevalue;
        if (attributename == null)
        {
            filter = null;
        }
        dircontext ctx = null;
        set set = new hashset();
        try
        {

            ctx = connectldap();

            searchcontrols constraints = new searchcontrols();
            constraints.setsearchscope(searchcontrols.subtree_scope);
            constraints.setcountlimit(0);
            for (int i = 0; i < attrs.length; i++)
            {
                string temp[] = new string[1];
                temp[0] = attrs[i];
                constraints.setreturningattributes(temp);

                string filter2 = "(&(" + filter + ")(" + temp[0] + "=*))";
                if (filter == null)
                {
                    filter2 = "(" + temp[0] + "=*)";
                }
                namingenumeration results = ctx.search(params.getbasedn(),
                    filter2, constraints);
                while (results.hasmoreelements())
                {
                    searchresult sr = (searchresult)results.next();
                    // should only be one attribute in the attribute set with
                    // one
                    // attribute value as byte array
                    namingenumeration enumeration = ((attribute)(sr
                        .getattributes().getall().next())).getall();
                    while (enumeration.hasmore())
                    {
                        object o = enumeration.next();
                        set.add(o);
                    }
                }
            }
        }
        catch (exception e)
        {
            throw new certstoreexception(
                "error getting results from ldap directory " + e);

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
        return set;
    }

}
