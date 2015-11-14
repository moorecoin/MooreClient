package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.extensions;

public class request
    extends asn1object
{
    certid            reqcert;
    extensions    singlerequestextensions;

    public request(
        certid          reqcert,
        extensions singlerequestextensions)
    {
        this.reqcert = reqcert;
        this.singlerequestextensions = singlerequestextensions;
    }

    private request(
        asn1sequence    seq)
    {
        reqcert = certid.getinstance(seq.getobjectat(0));

        if (seq.size() == 2)
        {
            singlerequestextensions = extensions.getinstance(
                                (asn1taggedobject)seq.getobjectat(1), true);
        }
    }

    public static request getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static request getinstance(
        object  obj)
    {
        if (obj instanceof request)
        {
            return (request)obj;
        }
        else if (obj != null)
        {
            return new request(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public certid getreqcert()
    {
        return reqcert;
    }

    public extensions getsinglerequestextensions()
    {
        return singlerequestextensions;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * request         ::=     sequence {
     *     reqcert                     certid,
     *     singlerequestextensions     [0] explicit extensions optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(reqcert);

        if (singlerequestextensions != null)
        {
            v.add(new dertaggedobject(true, 0, singlerequestextensions));
        }

        return new dersequence(v);
    }
}
