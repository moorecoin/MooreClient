package org.ripple.bouncycastle.asn1.cmp;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.generalname;

public class pkiheader
    extends asn1object
{
    /**
     * value for a "null" recipient or sender.
     */
    public static final generalname null_name = new generalname(x500name.getinstance(new dersequence()));

    public static final int cmp_1999 = 1;
    public static final int cmp_2000 = 2;

    private asn1integer pvno;
    private generalname sender;
    private generalname recipient;
    private dergeneralizedtime messagetime;
    private algorithmidentifier protectionalg;
    private asn1octetstring senderkid;       // keyidentifier
    private asn1octetstring recipkid;        // keyidentifier
    private asn1octetstring transactionid;
    private asn1octetstring sendernonce;
    private asn1octetstring recipnonce;
    private pkifreetext freetext;
    private asn1sequence generalinfo;

    private pkiheader(asn1sequence seq)
    {
        enumeration en = seq.getobjects();

        pvno = asn1integer.getinstance(en.nextelement());
        sender = generalname.getinstance(en.nextelement());
        recipient = generalname.getinstance(en.nextelement());

        while (en.hasmoreelements())
        {
            asn1taggedobject tobj = (asn1taggedobject)en.nextelement();

            switch (tobj.gettagno())
            {
            case 0:
                messagetime = dergeneralizedtime.getinstance(tobj, true);
                break;
            case 1:
                protectionalg = algorithmidentifier.getinstance(tobj, true);
                break;
            case 2:
                senderkid = asn1octetstring.getinstance(tobj, true);
                break;
            case 3:
                recipkid = asn1octetstring.getinstance(tobj, true);
                break;
            case 4:
                transactionid = asn1octetstring.getinstance(tobj, true);
                break;
            case 5:
                sendernonce = asn1octetstring.getinstance(tobj, true);
                break;
            case 6:
                recipnonce = asn1octetstring.getinstance(tobj, true);
                break;
            case 7:
                freetext = pkifreetext.getinstance(tobj, true);
                break;
            case 8:
                generalinfo = asn1sequence.getinstance(tobj, true);
                break;
            default:
                throw new illegalargumentexception("unknown tag number: " + tobj.gettagno());
            }
        }
    }

    public static pkiheader getinstance(object o)
    {
        if (o instanceof pkiheader)
        {
            return (pkiheader)o;
        }

        if (o != null)
        {
            return new pkiheader(asn1sequence.getinstance(o));
        }

        return null;
    }

    public pkiheader(
        int pvno,
        generalname sender,
        generalname recipient)
    {
        this(new asn1integer(pvno), sender, recipient);
    }

    private pkiheader(
        asn1integer pvno,
        generalname sender,
        generalname recipient)
    {
        this.pvno = pvno;
        this.sender = sender;
        this.recipient = recipient;
    }

    public asn1integer getpvno()
    {
        return pvno;
    }

    public generalname getsender()
    {
        return sender;
    }

    public generalname getrecipient()
    {
        return recipient;
    }

    public dergeneralizedtime getmessagetime()
    {
        return messagetime;
    }

    public algorithmidentifier getprotectionalg()
    {
        return protectionalg;
    }

    public asn1octetstring getsenderkid()
    {
        return senderkid;
    }

    public asn1octetstring getrecipkid()
    {
        return recipkid;
    }

    public asn1octetstring gettransactionid()
    {
        return transactionid;
    }

    public asn1octetstring getsendernonce()
    {
        return sendernonce;
    }

    public asn1octetstring getrecipnonce()
    {
        return recipnonce;
    }

    public pkifreetext getfreetext()
    {
        return freetext;
    }

    public infotypeandvalue[] getgeneralinfo()
    {
        if (generalinfo == null)
        {
            return null;
        }
        infotypeandvalue[] results = new infotypeandvalue[generalinfo.size()];
        for (int i = 0; i < results.length; i++)
        {
            results[i]
                = infotypeandvalue.getinstance(generalinfo.getobjectat(i));
        }
        return results;
    }

    /**
     * <pre>
     *  pkiheader ::= sequence {
     *            pvno                integer     { cmp1999(1), cmp2000(2) },
     *            sender              generalname,
     *            -- identifies the sender
     *            recipient           generalname,
     *            -- identifies the intended recipient
     *            messagetime     [0] generalizedtime         optional,
     *            -- time of production of this message (used when sender
     *            -- believes that the transport will be "suitable"; i.e.,
     *            -- that the time will still be meaningful upon receipt)
     *            protectionalg   [1] algorithmidentifier     optional,
     *            -- algorithm used for calculation of protection bits
     *            senderkid       [2] keyidentifier           optional,
     *            recipkid        [3] keyidentifier           optional,
     *            -- to identify specific keys used for protection
     *            transactionid   [4] octet string            optional,
     *            -- identifies the transaction; i.e., this will be the same in
     *            -- corresponding request, response, certconf, and pkiconf
     *            -- messages
     *            sendernonce     [5] octet string            optional,
     *            recipnonce      [6] octet string            optional,
     *            -- nonces used to provide replay protection, sendernonce
     *            -- is inserted by the creator of this message; recipnonce
     *            -- is a nonce previously inserted in a related message by
     *            -- the intended recipient of this message
     *            freetext        [7] pkifreetext             optional,
     *            -- this may be used to indicate context-specific instructions
     *            -- (this field is intended for human consumption)
     *            generalinfo     [8] sequence size (1..max) of
     *                                 infotypeandvalue     optional
     *            -- this may be used to convey context-specific information
     *            -- (this field not primarily intended for human consumption)
     * }
     * </pre>
     *
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(pvno);
        v.add(sender);
        v.add(recipient);
        addoptional(v, 0, messagetime);
        addoptional(v, 1, protectionalg);
        addoptional(v, 2, senderkid);
        addoptional(v, 3, recipkid);
        addoptional(v, 4, transactionid);
        addoptional(v, 5, sendernonce);
        addoptional(v, 6, recipnonce);
        addoptional(v, 7, freetext);
        addoptional(v, 8, generalinfo);

        return new dersequence(v);
    }

    private void addoptional(asn1encodablevector v, int tagno, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(new dertaggedobject(true, tagno, obj));
        }
    }
}
