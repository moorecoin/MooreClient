package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.cmp.pkistatusinfo;
import org.ripple.bouncycastle.asn1.x509.generalname;

/**
 * <pre>
 *     dvcserrornotice ::= sequence {
 *         transactionstatus           pkistatusinfo ,
 *         transactionidentifier       generalname optional
 *     }
 * </pre>
 */
public class dvcserrornotice
    extends asn1object
{
    private pkistatusinfo transactionstatus;
    private generalname transactionidentifier;

    public dvcserrornotice(pkistatusinfo status)
    {
        this(status, null);
    }

    public dvcserrornotice(pkistatusinfo status, generalname transactionidentifier)
    {
        this.transactionstatus = status;
        this.transactionidentifier = transactionidentifier;
    }

    private dvcserrornotice(asn1sequence seq)
    {
        this.transactionstatus = pkistatusinfo.getinstance(seq.getobjectat(0));
        if (seq.size() > 1)
        {
            this.transactionidentifier = generalname.getinstance(seq.getobjectat(1));
        }
    }

    public static dvcserrornotice getinstance(object obj)
    {
        if (obj instanceof dvcserrornotice)
        {
            return (dvcserrornotice)obj;
        }
        else if (obj != null)
        {
            return new dvcserrornotice(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static dvcserrornotice getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(transactionstatus);
        if (transactionidentifier != null)
        {
            v.add(transactionidentifier);
        }
        return new dersequence(v);
    }

    public string tostring()
    {
        return "dvcserrornotice {\n" +
            "transactionstatus: " + transactionstatus + "\n" +
            (transactionidentifier != null ? "transactionidentifier: " + transactionidentifier + "\n" : "") +
            "}\n";
    }


    public pkistatusinfo gettransactionstatus()
    {
        return transactionstatus;
    }

    public generalname gettransactionidentifier()
    {
        return transactionidentifier;
    }
}
