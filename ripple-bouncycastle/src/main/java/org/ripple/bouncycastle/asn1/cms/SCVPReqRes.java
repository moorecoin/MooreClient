package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class scvpreqres
    extends asn1object
{
    private final contentinfo request;
    private final contentinfo response;

    public static scvpreqres getinstance(
        object  obj)
    {
        if (obj instanceof scvpreqres)
        {
            return (scvpreqres)obj;
        }
        else if (obj != null)
        {
            return new scvpreqres(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private scvpreqres(
        asn1sequence seq)
    {
        if (seq.getobjectat(0) instanceof asn1taggedobject)
        {
            this.request = contentinfo.getinstance(asn1taggedobject.getinstance(seq.getobjectat(0)), true);
            this.response = contentinfo.getinstance(seq.getobjectat(1));
        }
        else
        {
            this.request = null;
            this.response = contentinfo.getinstance(seq.getobjectat(0));
        }
    }

    public scvpreqres(contentinfo response)
    {
        this.request = null;       // use of this confuses earlier jdks
        this.response = response;
    }

    public scvpreqres(contentinfo request, contentinfo response)
    {
        this.request = request;
        this.response = response;
    }

    public contentinfo getrequest()
    {
        return request;
    }

    public contentinfo getresponse()
    {
        return response;
    }

    /**
     * <pre>
     *    scvpreqres ::= sequence {
     *    request  [0] explicit contentinfo optional,
     *    response     contentinfo }
     * </pre>
     * @return  the asn.1 primitive representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        if (request != null)
        {
            v.add(new dertaggedobject(true, 0, request));
        }

        v.add(response);

        return new dersequence(v);
    }
}
