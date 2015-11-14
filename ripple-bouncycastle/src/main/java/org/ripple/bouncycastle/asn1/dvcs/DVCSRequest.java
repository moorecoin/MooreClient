package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.generalname;

/**
 * <pre>
 *     dvcsrequest ::= sequence  {
 *         requestinformation         dvcsrequestinformation,
 *         data                       data,
 *         transactionidentifier      generalname optional
 *     }
 * </pre>
 */

public class dvcsrequest
    extends asn1object
{

    private dvcsrequestinformation requestinformation;
    private data data;
    private generalname transactionidentifier;

    public dvcsrequest(dvcsrequestinformation requestinformation, data data)
    {
        this(requestinformation, data, null);
    }

    public dvcsrequest(dvcsrequestinformation requestinformation, data data, generalname transactionidentifier)
    {
        this.requestinformation = requestinformation;
        this.data = data;
        this.transactionidentifier = transactionidentifier;
    }

    private dvcsrequest(asn1sequence seq)
    {
        requestinformation = dvcsrequestinformation.getinstance(seq.getobjectat(0));
        data = data.getinstance(seq.getobjectat(1));
        if (seq.size() > 2)
        {
            transactionidentifier = generalname.getinstance(seq.getobjectat(2));
        }
    }

    public static dvcsrequest getinstance(object obj)
    {
        if (obj instanceof dvcsrequest)
        {
            return (dvcsrequest)obj;
        }
        else if (obj != null)
        {
            return new dvcsrequest(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static dvcsrequest getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(requestinformation);
        v.add(data);
        if (transactionidentifier != null)
        {
            v.add(transactionidentifier);
        }
        return new dersequence(v);
    }

    public string tostring()
    {
        return "dvcsrequest {\n" +
            "requestinformation: " + requestinformation + "\n" +
            "data: " + data + "\n" +
            (transactionidentifier != null ? "transactionidentifier: " + transactionidentifier + "\n" : "") +
            "}\n";
    }

    public data getdata()
    {
        return data;
    }

    public dvcsrequestinformation getrequestinformation()
    {
        return requestinformation;
    }

    public generalname gettransactionidentifier()
    {
        return transactionidentifier;
    }
}
