package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.x509extensions;

public class responsedata
    extends asn1object
{
    private static final asn1integer v1 = new asn1integer(0);
    
    private boolean             versionpresent;
    
    private asn1integer          version;
    private responderid         responderid;
    private asn1generalizedtime  producedat;
    private asn1sequence        responses;
    private extensions      responseextensions;

    public responsedata(
        asn1integer          version,
        responderid         responderid,
        asn1generalizedtime  producedat,
        asn1sequence        responses,
        extensions      responseextensions)
    {
        this.version = version;
        this.responderid = responderid;
        this.producedat = producedat;
        this.responses = responses;
        this.responseextensions = responseextensions;
    }

    /**
     * @deprecated use method taking extensions
     * @param responderid
     * @param producedat
     * @param responses
     * @param responseextensions
     */
    public responsedata(
        responderid         responderid,
        dergeneralizedtime  producedat,
        asn1sequence        responses,
        x509extensions responseextensions)
    {
        this(v1, responderid, asn1generalizedtime.getinstance(producedat), responses, extensions.getinstance(responseextensions));
    }

    public responsedata(
        responderid         responderid,
        asn1generalizedtime  producedat,
        asn1sequence        responses,
        extensions      responseextensions)
    {
        this(v1, responderid, producedat, responses, responseextensions);
    }
    
    private responsedata(
        asn1sequence    seq)
    {
        int index = 0;

        if (seq.getobjectat(0) instanceof asn1taggedobject)
        {
            asn1taggedobject    o = (asn1taggedobject)seq.getobjectat(0);

            if (o.gettagno() == 0)
            {
                this.versionpresent = true;
                this.version = asn1integer.getinstance(
                                (asn1taggedobject)seq.getobjectat(0), true);
                index++;
            }
            else
            {
                this.version = v1;
            }
        }
        else
        {
            this.version = v1;
        }

        this.responderid = responderid.getinstance(seq.getobjectat(index++));
        this.producedat = asn1generalizedtime.getinstance(seq.getobjectat(index++));
        this.responses = (asn1sequence)seq.getobjectat(index++);

        if (seq.size() > index)
        {
            this.responseextensions = extensions.getinstance(
                                (asn1taggedobject)seq.getobjectat(index), true);
        }
    }

    public static responsedata getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static responsedata getinstance(
        object  obj)
    {
        if (obj instanceof responsedata)
        {
            return (responsedata)obj;
        }
        else if (obj != null)
        {
            return new responsedata(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public asn1integer getversion()
    {
        return version;
    }

    public responderid getresponderid()
    {
        return responderid;
    }

    public asn1generalizedtime getproducedat()
    {
        return producedat;
    }

    public asn1sequence getresponses()
    {
        return responses;
    }

    public extensions getresponseextensions()
    {
        return responseextensions;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * responsedata ::= sequence {
     *     version              [0] explicit version default v1,
     *     responderid              responderid,
     *     producedat               generalizedtime,
     *     responses                sequence of singleresponse,
     *     responseextensions   [1] explicit extensions optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (versionpresent || !version.equals(v1))
        {
            v.add(new dertaggedobject(true, 0, version));
        }

        v.add(responderid);
        v.add(producedat);
        v.add(responses);
        if (responseextensions != null)
        {
            v.add(new dertaggedobject(true, 1, responseextensions));
        }

        return new dersequence(v);
    }
}
