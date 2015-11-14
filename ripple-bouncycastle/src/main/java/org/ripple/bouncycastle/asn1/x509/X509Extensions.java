package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derboolean;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * @deprecated use extensions
 */
public class x509extensions
    extends asn1object
{
    /**
     * subject directory attributes
     * @deprecated use x509extension value.
     */
    public static final asn1objectidentifier subjectdirectoryattributes = new asn1objectidentifier("2.5.29.9");
    
    /**
     * subject key identifier
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier subjectkeyidentifier = new asn1objectidentifier("2.5.29.14");

    /**
     * key usage
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier keyusage = new asn1objectidentifier("2.5.29.15");

    /**
     * private key usage period
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier privatekeyusageperiod = new asn1objectidentifier("2.5.29.16");

    /**
     * subject alternative name
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier subjectalternativename = new asn1objectidentifier("2.5.29.17");

    /**
     * issuer alternative name
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier issueralternativename = new asn1objectidentifier("2.5.29.18");

    /**
     * basic constraints
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier basicconstraints = new asn1objectidentifier("2.5.29.19");

    /**
     * crl number
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier crlnumber = new asn1objectidentifier("2.5.29.20");

    /**
     * reason code
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier reasoncode = new asn1objectidentifier("2.5.29.21");

    /**
     * hold instruction code
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier instructioncode = new asn1objectidentifier("2.5.29.23");

    /**
     * invalidity date
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier invaliditydate = new asn1objectidentifier("2.5.29.24");

    /**
     * delta crl indicator
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier deltacrlindicator = new asn1objectidentifier("2.5.29.27");

    /**
     * issuing distribution point
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier issuingdistributionpoint = new asn1objectidentifier("2.5.29.28");

    /**
     * certificate issuer
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier certificateissuer = new asn1objectidentifier("2.5.29.29");

    /**
     * name constraints
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier nameconstraints = new asn1objectidentifier("2.5.29.30");

    /**
     * crl distribution points
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier crldistributionpoints = new asn1objectidentifier("2.5.29.31");

    /**
     * certificate policies
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier certificatepolicies = new asn1objectidentifier("2.5.29.32");

    /**
     * policy mappings
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier policymappings = new asn1objectidentifier("2.5.29.33");

    /**
     * authority key identifier
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier authoritykeyidentifier = new asn1objectidentifier("2.5.29.35");

    /**
     * policy constraints
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier policyconstraints = new asn1objectidentifier("2.5.29.36");

    /**
     * extended key usage
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier extendedkeyusage = new asn1objectidentifier("2.5.29.37");

    /**
     * freshest crl
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier freshestcrl = new asn1objectidentifier("2.5.29.46");
     
    /**
     * inhibit any policy
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier inhibitanypolicy = new asn1objectidentifier("2.5.29.54");

    /**
     * authority info access
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier authorityinfoaccess = new asn1objectidentifier("1.3.6.1.5.5.7.1.1");

    /**
     * subject info access
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier subjectinfoaccess = new asn1objectidentifier("1.3.6.1.5.5.7.1.11");
    
    /**
     * logo type
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier logotype = new asn1objectidentifier("1.3.6.1.5.5.7.1.12");

    /**
     * biometricinfo
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier biometricinfo = new asn1objectidentifier("1.3.6.1.5.5.7.1.2");
    
    /**
     * qcstatements
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier qcstatements = new asn1objectidentifier("1.3.6.1.5.5.7.1.3");

    /**
     * audit identity extension in attribute certificates.
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier auditidentity = new asn1objectidentifier("1.3.6.1.5.5.7.1.4");
    
    /**
     * norevavail extension in attribute certificates.
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier norevavail = new asn1objectidentifier("2.5.29.56");

    /**
     * targetinformation extension in attribute certificates.
     *  @deprecated use x509extension value.
     */
    public static final asn1objectidentifier targetinformation = new asn1objectidentifier("2.5.29.55");
    
    private hashtable               extensions = new hashtable();
    private vector                  ordering = new vector();

    public static x509extensions getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static x509extensions getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof x509extensions)
        {
            return (x509extensions)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new x509extensions((asn1sequence)obj);
        }

        if (obj instanceof extensions)
        {
            return new x509extensions((asn1sequence)((extensions)obj).toasn1primitive());
        }

        if (obj instanceof asn1taggedobject)
        {
            return getinstance(((asn1taggedobject)obj).getobject());
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * constructor from asn1sequence.
     *
     * the extensions are a list of constructed sequences, either with (oid, octetstring) or (oid, boolean, octetstring)
     */
    public x509extensions(
        asn1sequence  seq)
    {
        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1sequence            s = asn1sequence.getinstance(e.nextelement());

            if (s.size() == 3)
            {
                extensions.put(s.getobjectat(0), new x509extension(derboolean.getinstance(s.getobjectat(1)), asn1octetstring.getinstance(s.getobjectat(2))));
            }
            else if (s.size() == 2)
            {
                extensions.put(s.getobjectat(0), new x509extension(false, asn1octetstring.getinstance(s.getobjectat(1))));
            }
            else
            {
                throw new illegalargumentexception("bad sequence size: " + s.size());
            }

            ordering.addelement(s.getobjectat(0));
        }
    }

    /**
     * constructor from a table of extensions.
     * <p>
     * it's is assumed the table contains oid/string pairs.
     */
    public x509extensions(
        hashtable  extensions)
    {
        this(null, extensions);
    }

    /**
     * constructor from a table of extensions with ordering.
     * <p>
     * it's is assumed the table contains oid/string pairs.
     * @deprecated use extensions
     */
    public x509extensions(
        vector      ordering,
        hashtable   extensions)
    {
        enumeration e;

        if (ordering == null)
        {
            e = extensions.keys();
        }
        else
        {
            e = ordering.elements();
        }

        while (e.hasmoreelements())
        {
            this.ordering.addelement(asn1objectidentifier.getinstance(e.nextelement()));
        }

        e = this.ordering.elements();

        while (e.hasmoreelements())
        {
            asn1objectidentifier     oid = asn1objectidentifier.getinstance(e.nextelement());
            x509extension           ext = (x509extension)extensions.get(oid);

            this.extensions.put(oid, ext);
        }
    }

    /**
     * constructor from two vectors
     * 
     * @param objectids a vector of the object identifiers.
     * @param values a vector of the extension values.
     * @deprecated use extensions
     */
    public x509extensions(
        vector      objectids,
        vector      values)
    {
        enumeration e = objectids.elements();

        while (e.hasmoreelements())
        {
            this.ordering.addelement(e.nextelement()); 
        }

        int count = 0;
        
        e = this.ordering.elements();

        while (e.hasmoreelements())
        {
            asn1objectidentifier     oid = (asn1objectidentifier)e.nextelement();
            x509extension           ext = (x509extension)values.elementat(count);

            this.extensions.put(oid, ext);
            count++;
        }
    }
    
    /**
     * return an enumeration of the extension field's object ids.
     */
    public enumeration oids()
    {
        return ordering.elements();
    }

    /**
     * return the extension represented by the object identifier
     * passed in.
     *
     * @return the extension if it's present, null otherwise.
     */
    public x509extension getextension(
        derobjectidentifier oid)
    {
        return (x509extension)extensions.get(oid);
    }

    /**
     * @deprecated
     * @param oid
     * @return
     */
    public x509extension getextension(
        asn1objectidentifier oid)
    {
        return (x509extension)extensions.get(oid);
    }

    /**
     * <pre>
     *     extensions        ::=   sequence size (1..max) of extension
     *
     *     extension         ::=   sequence {
     *        extnid            extension.&amp;id ({extensionset}),
     *        critical          boolean default false,
     *        extnvalue         octet string }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector     vec = new asn1encodablevector();
        enumeration             e = ordering.elements();

        while (e.hasmoreelements())
        {
            asn1objectidentifier    oid = (asn1objectidentifier)e.nextelement();
            x509extension           ext = (x509extension)extensions.get(oid);
            asn1encodablevector     v = new asn1encodablevector();

            v.add(oid);

            if (ext.iscritical())
            {
                v.add(derboolean.true);
            }

            v.add(ext.getvalue());

            vec.add(new dersequence(v));
        }

        return new dersequence(vec);
    }

    public boolean equivalent(
        x509extensions other)
    {
        if (extensions.size() != other.extensions.size())
        {
            return false;
        }

        enumeration     e1 = extensions.keys();

        while (e1.hasmoreelements())
        {
            object  key = e1.nextelement();

            if (!extensions.get(key).equals(other.extensions.get(key)))
            {
                return false;
            }
        }

        return true;
    }

    public asn1objectidentifier[] getextensionoids()
    {
        return tooidarray(ordering);
    }
    
    public asn1objectidentifier[] getnoncriticalextensionoids()
    {
        return getextensionoids(false);
    }

    public asn1objectidentifier[] getcriticalextensionoids()
    {
        return getextensionoids(true);
    }

    private asn1objectidentifier[] getextensionoids(boolean iscritical)
    {
        vector oidvec = new vector();

        for (int i = 0; i != ordering.size(); i++)
        {
            object oid = ordering.elementat(i);

            if (((x509extension)extensions.get(oid)).iscritical() == iscritical)
            {
                oidvec.addelement(oid);
            }
        }

        return tooidarray(oidvec);
    }

    private asn1objectidentifier[] tooidarray(vector oidvec)
    {
        asn1objectidentifier[] oids = new asn1objectidentifier[oidvec.size()];

        for (int i = 0; i != oids.length; i++)
        {
            oids[i] = (asn1objectidentifier)oidvec.elementat(i);
        }
        return oids;
    }
}
