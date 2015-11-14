package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

public class tbsrequest
    extends asn1object
{
    private static final asn1integer v1 = new asn1integer(0);
    
    asn1integer      version;
    generalname     requestorname;
    asn1sequence    requestlist;
    extensions  requestextensions;

    boolean         versionset;

    /**
     * @deprecated use method taking extensions
     * @param requestorname
     * @param requestlist
     * @param requestextensions
     */
    public tbsrequest(
        generalname     requestorname,
        asn1sequence    requestlist,
        x509extensions requestextensions)
    {
        this.version = v1;
        this.requestorname = requestorname;
        this.requestlist = requestlist;
        this.requestextensions = extensions.getinstance(requestextensions);
    }

    public tbsrequest(
        generalname     requestorname,
        asn1sequence    requestlist,
        extensions  requestextensions)
    {
        this.version = v1;
        this.requestorname = requestorname;
        this.requestlist = requestlist;
        this.requestextensions = requestextensions;
    }

    private tbsrequest(
        asn1sequence    seq)
    {
        int    index = 0;

        if (seq.getobjectat(0) instanceof asn1taggedobject)
        {
            asn1taggedobject    o = (asn1taggedobject)seq.getobjectat(0);

            if (o.gettagno() == 0)
            {
                versionset = true;
                version = asn1integer.getinstance((asn1taggedobject)seq.getobjectat(0), true);
                index++;
            }
            else
            {
                version = v1;
            }
        }
        else
        {
            version = v1;
        }

        if (seq.getobjectat(index) instanceof asn1taggedobject)
        {
            requestorname = generalname.getinstance((asn1taggedobject)seq.getobjectat(index++), true);
        }
        
        requestlist = (asn1sequence)seq.getobjectat(index++);

        if (seq.size() == (index + 1))
        {
            requestextensions = extensions.getinstance((asn1taggedobject)seq.getobjectat(index), true);
        }
    }

    public static tbsrequest getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static tbsrequest getinstance(
        object  obj)
    {
        if (obj instanceof tbsrequest)
        {
            return (tbsrequest)obj;
        }
        else if (obj != null)
        {
            return new tbsrequest(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public asn1integer getversion()
    {
        return version;
    }

    public generalname getrequestorname()
    {
        return requestorname;
    }

    public asn1sequence getrequestlist()
    {
        return requestlist;
    }

    public extensions getrequestextensions()
    {
        return requestextensions;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * tbsrequest      ::=     sequence {
     *     version             [0]     explicit version default v1,
     *     requestorname       [1]     explicit generalname optional,
     *     requestlist                 sequence of request,
     *     requestextensions   [2]     explicit extensions optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        //
        // if default don't include - unless explicitly provided. not strictly correct
        // but required for some requests
        //
        if (!version.equals(v1) || versionset)
        {
            v.add(new dertaggedobject(true, 0, version));
        }
        
        if (requestorname != null)
        {
            v.add(new dertaggedobject(true, 1, requestorname));
        }

        v.add(requestlist);

        if (requestextensions != null)
        {
            v.add(new dertaggedobject(true, 2, requestextensions));
        }

        return new dersequence(v);
    }
}
