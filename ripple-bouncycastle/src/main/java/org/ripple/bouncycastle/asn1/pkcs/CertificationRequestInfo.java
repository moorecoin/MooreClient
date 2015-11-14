package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509name;

/**
 * pkcs10 certificationrequestinfo object.
 * <pre>
 *  certificationrequestinfo ::= sequence {
 *   version             integer { v1(0) } (v1,...),
 *   subject             name,
 *   subjectpkinfo   subjectpublickeyinfo{{ pkinfoalgorithms }},
 *   attributes          [0] attributes{{ criattributes }}
 *  }
 *
 *  attributes { attribute:ioset } ::= set of attribute{{ ioset }}
 *
 *  attribute { attribute:ioset } ::= sequence {
 *    type    attribute.&id({ioset}),
 *    values  set size(1..max) of attribute.&type({ioset}{\@type})
 *  }
 * </pre>
 */
public class certificationrequestinfo
    extends asn1object
{
    asn1integer              version = new asn1integer(0);
    x500name                subject;
    subjectpublickeyinfo    subjectpkinfo;
    asn1set                 attributes = null;

    public static certificationrequestinfo getinstance(
        object  obj)
    {
        if (obj instanceof certificationrequestinfo)
        {
            return (certificationrequestinfo)obj;
        }
        else if (obj != null)
        {
            return new certificationrequestinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * basic constructor.
     * <p>
     * note: early on a lot of cas would only accept messages with attributes missing. as the asn.1 def shows
     * the attributes field is not optional so should always at least contain an empty set. if a fully compliant
     * request is required, pass in an empty set, the class will otherwise interpret a null as it should
     * encode the request with the field missing.
     * </p>
     *
     * @param subject subject to be associated with the public key
     * @param pkinfo public key to be associated with subject
     * @param attributes any attributes to be associated with the request.
     */
    public certificationrequestinfo(
        x500name subject,
        subjectpublickeyinfo    pkinfo,
        asn1set                 attributes)
    {
        this.subject = subject;
        this.subjectpkinfo = pkinfo;
        this.attributes = attributes;

        if ((subject == null) || (version == null) || (subjectpkinfo == null))
        {
            throw new illegalargumentexception("not all mandatory fields set in certificationrequestinfo generator.");
        }
    }

    /**
     * @deprecated use x500name method.
     */
    public certificationrequestinfo(
        x509name                subject,
        subjectpublickeyinfo    pkinfo,
        asn1set                 attributes)
    {
        this.subject = x500name.getinstance(subject.toasn1primitive());
        this.subjectpkinfo = pkinfo;
        this.attributes = attributes;

        if ((subject == null) || (version == null) || (subjectpkinfo == null))
        {
            throw new illegalargumentexception("not all mandatory fields set in certificationrequestinfo generator.");
        }
    }

    /**
     * @deprecated use getinstance().
     */
    public certificationrequestinfo(
        asn1sequence  seq)
    {
        version = (asn1integer)seq.getobjectat(0);

        subject = x500name.getinstance(seq.getobjectat(1));
        subjectpkinfo = subjectpublickeyinfo.getinstance(seq.getobjectat(2));

        //
        // some certificationrequestinfo objects seem to treat this field
        // as optional.
        //
        if (seq.size() > 3)
        {
            dertaggedobject tagobj = (dertaggedobject)seq.getobjectat(3);
            attributes = asn1set.getinstance(tagobj, false);
        }

        if ((subject == null) || (version == null) || (subjectpkinfo == null))
        {
            throw new illegalargumentexception("not all mandatory fields set in certificationrequestinfo generator.");
        }
    }

    public asn1integer getversion()
    {
        return version;
    }

    public x500name getsubject()
    {
        return subject;
    }

    public subjectpublickeyinfo getsubjectpublickeyinfo()
    {
        return subjectpkinfo;
    }

    public asn1set getattributes()
    {
        return attributes;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(subject);
        v.add(subjectpkinfo);

        if (attributes != null)
        {
            v.add(new dertaggedobject(false, 0, attributes));
        }

        return new dersequence(v);
    }
}
