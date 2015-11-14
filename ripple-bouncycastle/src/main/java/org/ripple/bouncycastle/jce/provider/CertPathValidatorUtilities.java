package org.ripple.bouncycastle.jce.provider;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.math.biginteger;
import java.security.generalsecurityexception;
import java.security.keyfactory;
import java.security.publickey;
import java.security.cert.crlexception;
import java.security.cert.certpath;
import java.security.cert.certpathvalidatorexception;
import java.security.cert.certstore;
import java.security.cert.certstoreexception;
import java.security.cert.certificate;
import java.security.cert.certificateparsingexception;
import java.security.cert.pkixparameters;
import java.security.cert.policyqualifierinfo;
import java.security.cert.trustanchor;
import java.security.cert.x509crl;
import java.security.cert.x509crlentry;
import java.security.cert.x509crlselector;
import java.security.cert.x509certselector;
import java.security.cert.x509certificate;
import java.security.interfaces.dsaparams;
import java.security.interfaces.dsapublickey;
import java.security.spec.dsapublickeyspec;
import java.text.parseexception;
import java.util.arraylist;
import java.util.collection;
import java.util.date;
import java.util.enumeration;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.map;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1outputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derenumerated;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.isismtt.isismttobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.crldistpoint;
import org.ripple.bouncycastle.asn1.x509.crlreason;
import org.ripple.bouncycastle.asn1.x509.distributionpoint;
import org.ripple.bouncycastle.asn1.x509.distributionpointname;
import org.ripple.bouncycastle.asn1.x509.extension;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.policyinformation;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509extension;
import org.ripple.bouncycastle.jce.x509ldapcertstoreparameters;
import org.ripple.bouncycastle.jce.exception.extcertpathvalidatorexception;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.util.selector;
import org.ripple.bouncycastle.util.storeexception;
import org.ripple.bouncycastle.x509.extendedpkixbuilderparameters;
import org.ripple.bouncycastle.x509.extendedpkixparameters;
import org.ripple.bouncycastle.x509.x509attributecertstoreselector;
import org.ripple.bouncycastle.x509.x509attributecertificate;
import org.ripple.bouncycastle.x509.x509crlstoreselector;
import org.ripple.bouncycastle.x509.x509certstoreselector;
import org.ripple.bouncycastle.x509.x509store;

public class certpathvalidatorutilities
{
    protected static final pkixcrlutil crl_util = new pkixcrlutil();

    protected static final string certificate_policies = extension.certificatepolicies.getid();
    protected static final string basic_constraints = extension.basicconstraints.getid();
    protected static final string policy_mappings = extension.policymappings.getid();
    protected static final string subject_alternative_name = extension.subjectalternativename.getid();
    protected static final string name_constraints = extension.nameconstraints.getid();
    protected static final string key_usage = extension.keyusage.getid();
    protected static final string inhibit_any_policy = extension.inhibitanypolicy.getid();
    protected static final string issuing_distribution_point = extension.issuingdistributionpoint.getid();
    protected static final string delta_crl_indicator = extension.deltacrlindicator.getid();
    protected static final string policy_constraints = extension.policyconstraints.getid();
    protected static final string freshest_crl = extension.freshestcrl.getid();
    protected static final string crl_distribution_points = extension.crldistributionpoints.getid();
    protected static final string authority_key_identifier = extension.authoritykeyidentifier.getid();

    protected static final string any_policy = "2.5.29.32.0";

    protected static final string crl_number = extension.crlnumber.getid();

    /*
    * key usage bits
    */
    protected static final int key_cert_sign = 5;
    protected static final int crl_sign = 6;

    protected static final string[] crlreasons = new string[]{
        "unspecified",
        "keycompromise",
        "cacompromise",
        "affiliationchanged",
        "superseded",
        "cessationofoperation",
        "certificatehold",
        "unknown",
        "removefromcrl",
        "privilegewithdrawn",
        "aacompromise"};

    /**
     * search the given set of trustanchor's for one that is the
     * issuer of the given x509 certificate. uses the default provider
     * for signature verification.
     *
     * @param cert         the x509 certificate
     * @param trustanchors a set of trustanchor's
     * @return the <code>trustanchor</code> object if found or
     *         <code>null</code> if not.
     * @throws annotatedexception if a trustanchor was found but the signature verification
     * on the given certificate has thrown an exception.
     */
    protected static trustanchor findtrustanchor(
        x509certificate cert,
        set trustanchors)
        throws annotatedexception
    {
        return findtrustanchor(cert, trustanchors, null);
    }

    /**
     * search the given set of trustanchor's for one that is the
     * issuer of the given x509 certificate. uses the specified
     * provider for signature verification, or the default provider
     * if null.
     *
     * @param cert         the x509 certificate
     * @param trustanchors a set of trustanchor's
     * @param sigprovider  the provider to use for signature verification
     * @return the <code>trustanchor</code> object if found or
     *         <code>null</code> if not.
     * @throws annotatedexception if a trustanchor was found but the signature verification
     * on the given certificate has thrown an exception.
     */
    protected static trustanchor findtrustanchor(
        x509certificate cert,
        set trustanchors,
        string sigprovider)
        throws annotatedexception
    {
        trustanchor trust = null;
        publickey trustpublickey = null;
        exception invalidkeyex = null;

        x509certselector certselectx509 = new x509certselector();
        x500principal certissuer = getencodedissuerprincipal(cert);

        try
        {
            certselectx509.setsubject(certissuer.getencoded());
        }
        catch (ioexception ex)
        {
            throw new annotatedexception("cannot set subject search criteria for trust anchor.", ex);
        }

        iterator iter = trustanchors.iterator();
        while (iter.hasnext() && trust == null)
        {
            trust = (trustanchor)iter.next();
            if (trust.gettrustedcert() != null)
            {
                if (certselectx509.match(trust.gettrustedcert()))
                {
                    trustpublickey = trust.gettrustedcert().getpublickey();
                }
                else
                {
                    trust = null;
                }
            }
            else if (trust.getcaname() != null
                && trust.getcapublickey() != null)
            {
                try
                {
                    x500principal caname = new x500principal(trust.getcaname());
                    if (certissuer.equals(caname))
                    {
                        trustpublickey = trust.getcapublickey();
                    }
                    else
                    {
                        trust = null;
                    }
                }
                catch (illegalargumentexception ex)
                {
                    trust = null;
                }
            }
            else
            {
                trust = null;
            }

            if (trustpublickey != null)
            {
                try
                {
                    verifyx509certificate(cert, trustpublickey, sigprovider);
                }
                catch (exception ex)
                {
                    invalidkeyex = ex;
                    trust = null;
                    trustpublickey = null;
                }
            }
        }

        if (trust == null && invalidkeyex != null)
        {
            throw new annotatedexception("trustanchor found but certificate validation failed.", invalidkeyex);
        }

        return trust;
    }

    protected static void addadditionalstoresfromaltnames(
        x509certificate cert,
        extendedpkixparameters pkixparams)
        throws certificateparsingexception
    {
        // if in the issueraltname extension an uri
        // is given, add an additinal x.509 store
        if (cert.getissueralternativenames() != null)
        {
            iterator it = cert.getissueralternativenames().iterator();
            while (it.hasnext())
            {
                // look for uri
                list list = (list)it.next();
                if (list.get(0).equals(integers.valueof(generalname.uniformresourceidentifier)))
                {
                    // found
                    string temp = (string)list.get(1);
                    certpathvalidatorutilities.addadditionalstorefromlocation(temp, pkixparams);
                }
            }
        }
    }

    /**
     * returns the issuer of an attribute certificate or certificate.
     *
     * @param cert the attribute certificate or certificate.
     * @return the issuer as <code>x500principal</code>.
     */
    protected static x500principal getencodedissuerprincipal(
        object cert)
    {
        if (cert instanceof x509certificate)
        {
            return ((x509certificate)cert).getissuerx500principal();
        }
        else
        {
            return (x500principal)((x509attributecertificate)cert).getissuer().getprincipals()[0];
        }
    }

    protected static date getvaliddate(pkixparameters paramspkix)
    {
        date validdate = paramspkix.getdate();

        if (validdate == null)
        {
            validdate = new date();
        }

        return validdate;
    }

    protected static x500principal getsubjectprincipal(x509certificate cert)
    {
        return cert.getsubjectx500principal();
    }

    protected static boolean isselfissued(x509certificate cert)
    {
        return cert.getsubjectdn().equals(cert.getissuerdn());
    }


    /**
     * extract the value of the given extension, if it exists.
     *
     * @param ext the extension object.
     * @param oid the object identifier to obtain.
     * @throws annotatedexception if the extension cannot be read.
     */
    protected static asn1primitive getextensionvalue(
        java.security.cert.x509extension ext,
        string oid)
        throws annotatedexception
    {
        byte[] bytes = ext.getextensionvalue(oid);
        if (bytes == null)
        {
            return null;
        }

        return getobject(oid, bytes);
    }

    private static asn1primitive getobject(
        string oid,
        byte[] ext)
        throws annotatedexception
    {
        try
        {
            asn1inputstream ain = new asn1inputstream(ext);
            asn1octetstring octs = (asn1octetstring)ain.readobject();

            ain = new asn1inputstream(octs.getoctets());
            return ain.readobject();
        }
        catch (exception e)
        {
            throw new annotatedexception("exception processing extension " + oid, e);
        }
    }

    protected static x500principal getissuerprincipal(x509crl crl)
    {
        return crl.getissuerx500principal();
    }

    protected static algorithmidentifier getalgorithmidentifier(
        publickey key)
        throws certpathvalidatorexception
    {
        try
        {
            asn1inputstream ain = new asn1inputstream(key.getencoded());

            subjectpublickeyinfo info = subjectpublickeyinfo.getinstance(ain.readobject());

            return info.getalgorithmid();
        }
        catch (exception e)
        {
            throw new extcertpathvalidatorexception("subject public key cannot be decoded.", e);
        }
    }

    // crl checking


    //
    // policy checking
    // 

    protected static final set getqualifierset(asn1sequence qualifiers)
        throws certpathvalidatorexception
    {
        set pq = new hashset();

        if (qualifiers == null)
        {
            return pq;
        }

        bytearrayoutputstream bout = new bytearrayoutputstream();
        asn1outputstream aout = new asn1outputstream(bout);

        enumeration e = qualifiers.getobjects();

        while (e.hasmoreelements())
        {
            try
            {
                aout.writeobject((asn1encodable)e.nextelement());

                pq.add(new policyqualifierinfo(bout.tobytearray()));
            }
            catch (ioexception ex)
            {
                throw new extcertpathvalidatorexception("policy qualifier info cannot be decoded.", ex);
            }

            bout.reset();
        }

        return pq;
    }

    protected static pkixpolicynode removepolicynode(
        pkixpolicynode validpolicytree,
        list[] policynodes,
        pkixpolicynode _node)
    {
        pkixpolicynode _parent = (pkixpolicynode)_node.getparent();

        if (validpolicytree == null)
        {
            return null;
        }

        if (_parent == null)
        {
            for (int j = 0; j < policynodes.length; j++)
            {
                policynodes[j] = new arraylist();
            }

            return null;
        }
        else
        {
            _parent.removechild(_node);
            removepolicynoderecurse(policynodes, _node);

            return validpolicytree;
        }
    }

    private static void removepolicynoderecurse(
        list[] policynodes,
        pkixpolicynode _node)
    {
        policynodes[_node.getdepth()].remove(_node);

        if (_node.haschildren())
        {
            iterator _iter = _node.getchildren();
            while (_iter.hasnext())
            {
                pkixpolicynode _child = (pkixpolicynode)_iter.next();
                removepolicynoderecurse(policynodes, _child);
            }
        }
    }


    protected static boolean processcertd1i(
        int index,
        list[] policynodes,
        derobjectidentifier poid,
        set pq)
    {
        list policynodevec = policynodes[index - 1];

        for (int j = 0; j < policynodevec.size(); j++)
        {
            pkixpolicynode node = (pkixpolicynode)policynodevec.get(j);
            set expectedpolicies = node.getexpectedpolicies();

            if (expectedpolicies.contains(poid.getid()))
            {
                set childexpectedpolicies = new hashset();
                childexpectedpolicies.add(poid.getid());

                pkixpolicynode child = new pkixpolicynode(new arraylist(),
                    index,
                    childexpectedpolicies,
                    node,
                    pq,
                    poid.getid(),
                    false);
                node.addchild(child);
                policynodes[index].add(child);

                return true;
            }
        }

        return false;
    }

    protected static void processcertd1ii(
        int index,
        list[] policynodes,
        derobjectidentifier _poid,
        set _pq)
    {
        list policynodevec = policynodes[index - 1];

        for (int j = 0; j < policynodevec.size(); j++)
        {
            pkixpolicynode _node = (pkixpolicynode)policynodevec.get(j);

            if (any_policy.equals(_node.getvalidpolicy()))
            {
                set _childexpectedpolicies = new hashset();
                _childexpectedpolicies.add(_poid.getid());

                pkixpolicynode _child = new pkixpolicynode(new arraylist(),
                    index,
                    _childexpectedpolicies,
                    _node,
                    _pq,
                    _poid.getid(),
                    false);
                _node.addchild(_child);
                policynodes[index].add(_child);
                return;
            }
        }
    }

    protected static void preparenextcertb1(
        int i,
        list[] policynodes,
        string id_p,
        map m_idp,
        x509certificate cert
    )
        throws annotatedexception, certpathvalidatorexception
    {
        boolean idp_found = false;
        iterator nodes_i = policynodes[i].iterator();
        while (nodes_i.hasnext())
        {
            pkixpolicynode node = (pkixpolicynode)nodes_i.next();
            if (node.getvalidpolicy().equals(id_p))
            {
                idp_found = true;
                node.expectedpolicies = (set)m_idp.get(id_p);
                break;
            }
        }

        if (!idp_found)
        {
            nodes_i = policynodes[i].iterator();
            while (nodes_i.hasnext())
            {
                pkixpolicynode node = (pkixpolicynode)nodes_i.next();
                if (any_policy.equals(node.getvalidpolicy()))
                {
                    set pq = null;
                    asn1sequence policies = null;
                    try
                    {
                        policies = dersequence.getinstance(getextensionvalue(cert, certificate_policies));
                    }
                    catch (exception e)
                    {
                        throw new annotatedexception("certificate policies cannot be decoded.", e);
                    }
                    enumeration e = policies.getobjects();
                    while (e.hasmoreelements())
                    {
                        policyinformation pinfo = null;

                        try
                        {
                            pinfo = policyinformation.getinstance(e.nextelement());
                        }
                        catch (exception ex)
                        {
                            throw new annotatedexception("policy information cannot be decoded.", ex);
                        }
                        if (any_policy.equals(pinfo.getpolicyidentifier().getid()))
                        {
                            try
                            {
                                pq = getqualifierset(pinfo.getpolicyqualifiers());
                            }
                            catch (certpathvalidatorexception ex)
                            {
                                throw new extcertpathvalidatorexception(
                                    "policy qualifier info set could not be built.", ex);
                            }
                            break;
                        }
                    }
                    boolean ci = false;
                    if (cert.getcriticalextensionoids() != null)
                    {
                        ci = cert.getcriticalextensionoids().contains(certificate_policies);
                    }

                    pkixpolicynode p_node = (pkixpolicynode)node.getparent();
                    if (any_policy.equals(p_node.getvalidpolicy()))
                    {
                        pkixpolicynode c_node = new pkixpolicynode(
                            new arraylist(), i,
                            (set)m_idp.get(id_p),
                            p_node, pq, id_p, ci);
                        p_node.addchild(c_node);
                        policynodes[i].add(c_node);
                    }
                    break;
                }
            }
        }
    }

    protected static pkixpolicynode preparenextcertb2(
        int i,
        list[] policynodes,
        string id_p,
        pkixpolicynode validpolicytree)
    {
        iterator nodes_i = policynodes[i].iterator();
        while (nodes_i.hasnext())
        {
            pkixpolicynode node = (pkixpolicynode)nodes_i.next();
            if (node.getvalidpolicy().equals(id_p))
            {
                pkixpolicynode p_node = (pkixpolicynode)node.getparent();
                p_node.removechild(node);
                nodes_i.remove();
                for (int k = (i - 1); k >= 0; k--)
                {
                    list nodes = policynodes[k];
                    for (int l = 0; l < nodes.size(); l++)
                    {
                        pkixpolicynode node2 = (pkixpolicynode)nodes.get(l);
                        if (!node2.haschildren())
                        {
                            validpolicytree = removepolicynode(validpolicytree, policynodes, node2);
                            if (validpolicytree == null)
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }
        return validpolicytree;
    }

    protected static boolean isanypolicy(
        set policyset)
    {
        return policyset == null || policyset.contains(any_policy) || policyset.isempty();
    }

    protected static void addadditionalstorefromlocation(string location,
                                                         extendedpkixparameters pkixparams)
    {
        if (pkixparams.isadditionallocationsenabled())
        {
            try
            {
                if (location.startswith("ldap://"))
                {
                    // ldap://directory.d-trust.net/cn=d-trust
                    // qualified ca 2003 1:pn,o=d-trust gmbh,c=de
                    // skip "ldap://"
                    location = location.substring(7);
                    // after first / basedn starts
                    string base = null;
                    string url = null;
                    if (location.indexof("/") != -1)
                    {
                        base = location.substring(location.indexof("/"));
                        // url
                        url = "ldap://"
                            + location.substring(0, location.indexof("/"));
                    }
                    else
                    {
                        url = "ldap://" + location;
                    }
                    // use all purpose parameters
                    x509ldapcertstoreparameters params = new x509ldapcertstoreparameters.builder(
                        url, base).build();
                    pkixparams.addadditionalstore(x509store.getinstance(
                        "certificate/ldap", params, bouncycastleprovider.provider_name));
                    pkixparams.addadditionalstore(x509store.getinstance(
                        "crl/ldap", params, bouncycastleprovider.provider_name));
                    pkixparams.addadditionalstore(x509store.getinstance(
                        "attributecertificate/ldap", params, bouncycastleprovider.provider_name));
                    pkixparams.addadditionalstore(x509store.getinstance(
                        "certificatepair/ldap", params, bouncycastleprovider.provider_name));
                }
            }
            catch (exception e)
            {
                // cannot happen
                throw new runtimeexception("exception adding x.509 stores.");
            }
        }
    }

    /**
     * return a collection of all certificates or attribute certificates found
     * in the x509store's that are matching the certselect criteriums.
     *
     * @param certselect a {@link selector} object that will be used to select
     *                   the certificates
     * @param certstores a list containing only {@link x509store} objects. these
     *                   are used to search for certificates.
     * @return a collection of all found {@link x509certificate} or
     *         {@link org.ripple.bouncycastle.x509.x509attributecertificate} objects.
     *         may be empty but never <code>null</code>.
     */
    protected static collection findcertificates(x509certstoreselector certselect,
                                                 list certstores)
        throws annotatedexception
    {
        set certs = new hashset();
        iterator iter = certstores.iterator();

        while (iter.hasnext())
        {
            object obj = iter.next();

            if (obj instanceof x509store)
            {
                x509store certstore = (x509store)obj;
                try
                {
                    certs.addall(certstore.getmatches(certselect));
                }
                catch (storeexception e)
                {
                    throw new annotatedexception(
                            "problem while picking certificates from x.509 store.", e);
                }
            }
            else
            {
                certstore certstore = (certstore)obj;

                try
                {
                    certs.addall(certstore.getcertificates(certselect));
                }
                catch (certstoreexception e)
                {
                    throw new annotatedexception(
                        "problem while picking certificates from certificate store.",
                        e);
                }
            }
        }
        return certs;
    }

    protected static collection findcertificates(x509attributecertstoreselector certselect,
                                                 list certstores)
        throws annotatedexception
    {
        set certs = new hashset();
        iterator iter = certstores.iterator();

        while (iter.hasnext())
        {
            object obj = iter.next();

            if (obj instanceof x509store)
            {
                x509store certstore = (x509store)obj;
                try
                {
                    certs.addall(certstore.getmatches(certselect));
                }
                catch (storeexception e)
                {
                    throw new annotatedexception(
                            "problem while picking certificates from x.509 store.", e);
                }
            }
        }
        return certs;
    }

    protected static void addadditionalstoresfromcrldistributionpoint(
        crldistpoint crldp, extendedpkixparameters pkixparams)
        throws annotatedexception
    {
        if (crldp != null)
        {
            distributionpoint dps[] = null;
            try
            {
                dps = crldp.getdistributionpoints();
            }
            catch (exception e)
            {
                throw new annotatedexception(
                    "distribution points could not be read.", e);
            }
            for (int i = 0; i < dps.length; i++)
            {
                distributionpointname dpn = dps[i].getdistributionpoint();
                // look for uris in fullname
                if (dpn != null)
                {
                    if (dpn.gettype() == distributionpointname.full_name)
                    {
                        generalname[] gennames = generalnames.getinstance(
                            dpn.getname()).getnames();
                        // look for an uri
                        for (int j = 0; j < gennames.length; j++)
                        {
                            if (gennames[j].gettagno() == generalname.uniformresourceidentifier)
                            {
                                string location = deria5string.getinstance(
                                    gennames[j].getname()).getstring();
                                certpathvalidatorutilities
                                    .addadditionalstorefromlocation(location,
                                        pkixparams);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * add the crl issuers from the crlissuer field of the distribution point or
     * from the certificate if not given to the issuer criterion of the
     * <code>selector</code>.
     * <p/>
     * the <code>issuerprincipals</code> are a collection with a single
     * <code>x500principal</code> for <code>x509certificate</code>s. for
     * {@link x509attributecertificate}s the issuer may contain more than one
     * <code>x500principal</code>.
     *
     * @param dp               the distribution point.
     * @param issuerprincipals the issuers of the certificate or attribute
     *                         certificate which contains the distribution point.
     * @param selector         the crl selector.
     * @param pkixparams       the pkix parameters containing the cert stores.
     * @throws annotatedexception if an exception occurs while processing.
     * @throws classcastexception if <code>issuerprincipals</code> does not
     * contain only <code>x500principal</code>s.
     */
    protected static void getcrlissuersfromdistributionpoint(
        distributionpoint dp,
        collection issuerprincipals,
        x509crlselector selector,
        extendedpkixparameters pkixparams)
        throws annotatedexception
    {
        list issuers = new arraylist();
        // indirect crl
        if (dp.getcrlissuer() != null)
        {
            generalname gennames[] = dp.getcrlissuer().getnames();
            // look for a dn
            for (int j = 0; j < gennames.length; j++)
            {
                if (gennames[j].gettagno() == generalname.directoryname)
                {
                    try
                    {
                        issuers.add(new x500principal(gennames[j].getname()
                            .toasn1primitive().getencoded()));
                    }
                    catch (ioexception e)
                    {
                        throw new annotatedexception(
                            "crl issuer information from distribution point cannot be decoded.",
                            e);
                    }
                }
            }
        }
        else
        {
            /*
             * certificate issuer is crl issuer, distributionpoint field must be
             * present.
             */
            if (dp.getdistributionpoint() == null)
            {
                throw new annotatedexception(
                    "crl issuer is omitted from distribution point but no distributionpoint field present.");
            }
            // add and check issuer principals
            for (iterator it = issuerprincipals.iterator(); it.hasnext(); )
            {
                issuers.add((x500principal)it.next());
            }
        }
        // todo: is not found although this should correctly add the rel name. selector of sun is buggy here or pki test case is invalid
        // distributionpoint
//        if (dp.getdistributionpoint() != null)
//        {
//            // look for namerelativetocrlissuer
//            if (dp.getdistributionpoint().gettype() == distributionpointname.name_relative_to_crl_issuer)
//            {
//                // append fragment to issuer, only one
//                // issuer can be there, if this is given
//                if (issuers.size() != 1)
//                {
//                    throw new annotatedexception(
//                        "namerelativetocrlissuer field is given but more than one crl issuer is given.");
//                }
//                asn1encodable relname = dp.getdistributionpoint().getname();
//                iterator it = issuers.iterator();
//                list issuerstemp = new arraylist(issuers.size());
//                while (it.hasnext())
//                {
//                    enumeration e = null;
//                    try
//                    {
//                        e = asn1sequence.getinstance(
//                            new asn1inputstream(((x500principal) it.next())
//                                .getencoded()).readobject()).getobjects();
//                    }
//                    catch (ioexception ex)
//                    {
//                        throw new annotatedexception(
//                            "cannot decode crl issuer information.", ex);
//                    }
//                    asn1encodablevector v = new asn1encodablevector();
//                    while (e.hasmoreelements())
//                    {
//                        v.add((asn1encodable) e.nextelement());
//                    }
//                    v.add(relname);
//                    issuerstemp.add(new x500principal(new dersequence(v)
//                        .getderencoded()));
//                }
//                issuers.clear();
//                issuers.addall(issuerstemp);
//            }
//        }
        iterator it = issuers.iterator();
        while (it.hasnext())
        {
            try
            {
                selector.addissuername(((x500principal)it.next()).getencoded());
            }
            catch (ioexception ex)
            {
                throw new annotatedexception(
                    "cannot decode crl issuer information.", ex);
            }
        }
    }

    private static biginteger getserialnumber(
        object cert)
    {
        if (cert instanceof x509certificate)
        {
            return ((x509certificate)cert).getserialnumber();
        }
        else
        {
            return ((x509attributecertificate)cert).getserialnumber();
        }
    }

    protected static void getcertstatus(
        date validdate,
        x509crl crl,
        object cert,
        certstatus certstatus)
        throws annotatedexception
    {
        x509crlentry crl_entry = null;

        boolean isindirect;
        try
        {
            isindirect = x509crlobject.isindirectcrl(crl);
        }
        catch (crlexception exception)
        {
            throw new annotatedexception("failed check for indirect crl.", exception);
        }

        if (isindirect)
        {
            crl_entry = crl.getrevokedcertificate(getserialnumber(cert));

            if (crl_entry == null)
            {
                return;
            }

            x500principal certissuer = crl_entry.getcertificateissuer();

            if (certissuer == null)
            {
                certissuer = getissuerprincipal(crl);
            }

            if (!getencodedissuerprincipal(cert).equals(certissuer))
            {
                return;
            }
        }
        else if (!getencodedissuerprincipal(cert).equals(getissuerprincipal(crl)))
        {
            return;  // not for our issuer, ignore
        }
        else
        {
            crl_entry = crl.getrevokedcertificate(getserialnumber(cert));

            if (crl_entry == null)
            {
                return;
            }
        }

        derenumerated reasoncode = null;
        if (crl_entry.hasextensions())
        {
            try
            {
                reasoncode = derenumerated
                    .getinstance(certpathvalidatorutilities
                        .getextensionvalue(crl_entry,
                            x509extension.reasoncode.getid()));
            }
            catch (exception e)
            {
                throw new annotatedexception(
                    "reason code crl entry extension could not be decoded.",
                    e);
            }
        }

        // for reason keycompromise, cacompromise, aacompromise or
        // unspecified
        if (!(validdate.gettime() < crl_entry.getrevocationdate().gettime())
            || reasoncode == null
            || reasoncode.getvalue().intvalue() == 0
            || reasoncode.getvalue().intvalue() == 1
            || reasoncode.getvalue().intvalue() == 2
            || reasoncode.getvalue().intvalue() == 8)
        {

            // (i) or (j) (1)
            if (reasoncode != null)
            {
                certstatus.setcertstatus(reasoncode.getvalue().intvalue());
            }
            // (i) or (j) (2)
            else
            {
                certstatus.setcertstatus(crlreason.unspecified);
            }
            certstatus.setrevocationdate(crl_entry.getrevocationdate());
        }
    }

    /**
     * fetches delta crls according to rfc 3280 section 5.2.4.
     *
     * @param currentdate the date for which the delta crls must be valid.
     * @param paramspkix  the extended pkix parameters.
     * @param completecrl the complete crl the delta crl is for.
     * @return a <code>set</code> of <code>x509crl</code>s with delta crls.
     * @throws annotatedexception if an exception occurs while picking the delta
     * crls.
     */
    protected static set getdeltacrls(date currentdate,
                                      extendedpkixparameters paramspkix, x509crl completecrl)
        throws annotatedexception
    {

        x509crlstoreselector deltaselect = new x509crlstoreselector();

        // 5.2.4 (a)
        try
        {
            deltaselect.addissuername(certpathvalidatorutilities
                .getissuerprincipal(completecrl).getencoded());
        }
        catch (ioexception e)
        {
            throw new annotatedexception("cannot extract issuer from crl.", e);
        }

        biginteger completecrlnumber = null;
        try
        {
            asn1primitive derobject = certpathvalidatorutilities.getextensionvalue(completecrl,
                crl_number);
            if (derobject != null)
            {
                completecrlnumber = asn1integer.getinstance(derobject).getpositivevalue();
            }
        }
        catch (exception e)
        {
            throw new annotatedexception(
                "crl number extension could not be extracted from crl.", e);
        }

        // 5.2.4 (b)
        byte[] idp = null;
        try
        {
            idp = completecrl.getextensionvalue(issuing_distribution_point);
        }
        catch (exception e)
        {
            throw new annotatedexception(
                "issuing distribution point extension value could not be read.",
                e);
        }

        // 5.2.4 (d)

        deltaselect.setmincrlnumber(completecrlnumber == null ? null : completecrlnumber
            .add(biginteger.valueof(1)));

        deltaselect.setissuingdistributionpoint(idp);
        deltaselect.setissuingdistributionpointenabled(true);

        // 5.2.4 (c)
        deltaselect.setmaxbasecrlnumber(completecrlnumber);

        // find delta crls
        set temp = crl_util.findcrls(deltaselect, paramspkix, currentdate);

        set result = new hashset();

        for (iterator it = temp.iterator(); it.hasnext(); )
        {
            x509crl crl = (x509crl)it.next();

            if (isdeltacrl(crl))
            {
                result.add(crl);
            }
        }

        return result;
    }

    private static boolean isdeltacrl(x509crl crl)
    {
        set critical = crl.getcriticalextensionoids();

        if (critical == null)
        {
            return false;
        }

        return critical.contains(rfc3280certpathutilities.delta_crl_indicator);
    }

    /**
     * fetches complete crls according to rfc 3280.
     *
     * @param dp          the distribution point for which the complete crl
     * @param cert        the <code>x509certificate</code> or
     *                    {@link org.ripple.bouncycastle.x509.x509attributecertificate} for
     *                    which the crl should be searched.
     * @param currentdate the date for which the delta crls must be valid.
     * @param paramspkix  the extended pkix parameters.
     * @return a <code>set</code> of <code>x509crl</code>s with complete
     *         crls.
     * @throws annotatedexception if an exception occurs while picking the crls
     * or no crls are found.
     */
    protected static set getcompletecrls(distributionpoint dp, object cert,
                                         date currentdate, extendedpkixparameters paramspkix)
        throws annotatedexception
    {
        x509crlstoreselector crlselect = new x509crlstoreselector();
        try
        {
            set issuers = new hashset();
            if (cert instanceof x509attributecertificate)
            {
                issuers.add(((x509attributecertificate)cert)
                    .getissuer().getprincipals()[0]);
            }
            else
            {
                issuers.add(getencodedissuerprincipal(cert));
            }
            certpathvalidatorutilities.getcrlissuersfromdistributionpoint(dp, issuers, crlselect, paramspkix);
        }
        catch (annotatedexception e)
        {
            throw new annotatedexception(
                "could not get issuer information from distribution point.", e);
        }
        if (cert instanceof x509certificate)
        {
            crlselect.setcertificatechecking((x509certificate)cert);
        }
        else if (cert instanceof x509attributecertificate)
        {
            crlselect.setattrcertificatechecking((x509attributecertificate)cert);
        }


        crlselect.setcompletecrlenabled(true);

        set crls = crl_util.findcrls(crlselect, paramspkix, currentdate);

        if (crls.isempty())
        {
            if (cert instanceof x509attributecertificate)
            {
                x509attributecertificate acert = (x509attributecertificate)cert;

                throw new annotatedexception("no crls found for issuer \"" + acert.getissuer().getprincipals()[0] + "\"");
            }
            else
            {
                x509certificate xcert = (x509certificate)cert;

                throw new annotatedexception("no crls found for issuer \"" + xcert.getissuerx500principal() + "\"");
            }
        }
        return crls;
    }

    protected static date getvalidcertdatefromvaliditymodel(
        extendedpkixparameters paramspkix, certpath certpath, int index)
        throws annotatedexception
    {
        if (paramspkix.getvaliditymodel() == extendedpkixparameters.chain_validity_model)
        {
            // if end cert use given signing/encryption/... time
            if (index <= 0)
            {
                return certpathvalidatorutilities.getvaliddate(paramspkix);
                // else use time when previous cert was created
            }
            else
            {
                if (index - 1 == 0)
                {
                    dergeneralizedtime dateofcertgen = null;
                    try
                    {
                        byte[] extbytes = ((x509certificate)certpath.getcertificates().get(index - 1)).getextensionvalue(isismttobjectidentifiers.id_isismtt_at_dateofcertgen.getid());
                        if (extbytes != null)
                        {
                            dateofcertgen = dergeneralizedtime.getinstance(asn1primitive.frombytearray(extbytes));
                        }
                    }
                    catch (ioexception e)
                    {
                        throw new annotatedexception(
                            "date of cert gen extension could not be read.");
                    }
                    catch (illegalargumentexception e)
                    {
                        throw new annotatedexception(
                            "date of cert gen extension could not be read.");
                    }
                    if (dateofcertgen != null)
                    {
                        try
                        {
                            return dateofcertgen.getdate();
                        }
                        catch (parseexception e)
                        {
                            throw new annotatedexception(
                                "date from date of cert gen extension could not be parsed.",
                                e);
                        }
                    }
                    return ((x509certificate)certpath.getcertificates().get(
                        index - 1)).getnotbefore();
                }
                else
                {
                    return ((x509certificate)certpath.getcertificates().get(
                        index - 1)).getnotbefore();
                }
            }
        }
        else
        {
            return getvaliddate(paramspkix);
        }
    }

    /**
     * return the next working key inheriting dsa parameters if necessary.
     * <p>
     * this methods inherits dsa parameters from the indexed certificate or
     * previous certificates in the certificate chain to the returned
     * <code>publickey</code>. the list is searched upwards, meaning the end
     * certificate is at position 0 and previous certificates are following.
     * </p>
     * <p>
     * if the indexed certificate does not contain a dsa key this method simply
     * returns the public key. if the dsa key already contains dsa parameters
     * the key is also only returned.
     * </p>
     *
     * @param certs the certification path.
     * @param index the index of the certificate which contains the public key
     *              which should be extended with dsa parameters.
     * @return the public key of the certificate in list position
     *         <code>index</code> extended with dsa parameters if applicable.
     * @throws annotatedexception if dsa parameters cannot be inherited.
     */
    protected static publickey getnextworkingkey(list certs, int index)
        throws certpathvalidatorexception
    {
        certificate cert = (certificate)certs.get(index);
        publickey pubkey = cert.getpublickey();
        if (!(pubkey instanceof dsapublickey))
        {
            return pubkey;
        }
        dsapublickey dsapubkey = (dsapublickey)pubkey;
        if (dsapubkey.getparams() != null)
        {
            return dsapubkey;
        }
        for (int i = index + 1; i < certs.size(); i++)
        {
            x509certificate parentcert = (x509certificate)certs.get(i);
            pubkey = parentcert.getpublickey();
            if (!(pubkey instanceof dsapublickey))
            {
                throw new certpathvalidatorexception(
                    "dsa parameters cannot be inherited from previous certificate.");
            }
            dsapublickey prevdsapubkey = (dsapublickey)pubkey;
            if (prevdsapubkey.getparams() == null)
            {
                continue;
            }
            dsaparams dsaparams = prevdsapubkey.getparams();
            dsapublickeyspec dsapubkeyspec = new dsapublickeyspec(
                dsapubkey.gety(), dsaparams.getp(), dsaparams.getq(), dsaparams.getg());
            try
            {
                keyfactory keyfactory = keyfactory.getinstance("dsa", bouncycastleprovider.provider_name);
                return keyfactory.generatepublic(dsapubkeyspec);
            }
            catch (exception exception)
            {
                throw new runtimeexception(exception.getmessage());
            }
        }
        throw new certpathvalidatorexception("dsa parameters cannot be inherited from previous certificate.");
    }

    /**
     * find the issuer certificates of a given certificate.
     *
     * @param cert       the certificate for which an issuer should be found.
     * @param pkixparams
     * @return a <code>collection</code> object containing the issuer
     *         <code>x509certificate</code>s. never <code>null</code>.
     * @throws annotatedexception if an error occurs.
     */
    protected static collection findissuercerts(
        x509certificate cert,
        extendedpkixbuilderparameters pkixparams)
        throws annotatedexception
    {
        x509certstoreselector certselect = new x509certstoreselector();
        set certs = new hashset();
        try
        {
            certselect.setsubject(cert.getissuerx500principal().getencoded());
        }
        catch (ioexception ex)
        {
            throw new annotatedexception(
                "subject criteria for certificate selector to find issuer certificate could not be set.", ex);
        }

        iterator iter;

        try
        {
            list matches = new arraylist();

            matches.addall(certpathvalidatorutilities.findcertificates(certselect, pkixparams.getcertstores()));
            matches.addall(certpathvalidatorutilities.findcertificates(certselect, pkixparams.getstores()));
            matches.addall(certpathvalidatorutilities.findcertificates(certselect, pkixparams.getadditionalstores()));

            iter = matches.iterator();
        }
        catch (annotatedexception e)
        {
            throw new annotatedexception("issuer certificate cannot be searched.", e);
        }

        x509certificate issuer = null;
        while (iter.hasnext())
        {
            issuer = (x509certificate)iter.next();
            // issuer cannot be verified because possible dsa inheritance
            // parameters are missing
            certs.add(issuer);
        }
        return certs;
    }

    protected static void verifyx509certificate(x509certificate cert, publickey publickey,
                                                string sigprovider)
        throws generalsecurityexception
    {
        if (sigprovider == null)
        {
            cert.verify(publickey);
        }
        else
        {
            cert.verify(publickey, sigprovider);
        }
    }
}
