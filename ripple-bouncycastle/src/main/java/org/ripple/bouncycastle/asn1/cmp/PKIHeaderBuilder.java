package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.generalname;

public class pkiheaderbuilder
{
    private asn1integer pvno;
    private generalname sender;
    private generalname recipient;
    private asn1generalizedtime messagetime;
    private algorithmidentifier protectionalg;
    private asn1octetstring senderkid;       // keyidentifier
    private asn1octetstring recipkid;        // keyidentifier
    private asn1octetstring transactionid;
    private asn1octetstring sendernonce;
    private asn1octetstring recipnonce;
    private pkifreetext     freetext;
    private asn1sequence    generalinfo;

    public pkiheaderbuilder(
        int pvno,
        generalname sender,
        generalname recipient)
    {
        this(new asn1integer(pvno), sender, recipient);
    }

    private pkiheaderbuilder(
        asn1integer pvno,
        generalname sender,
        generalname recipient)
    {
        this.pvno = pvno;
        this.sender = sender;
        this.recipient = recipient;
    }

    /**
     * @deprecated use asn1generalizedtime
     */
    public pkiheaderbuilder setmessagetime(dergeneralizedtime time)
    {
        messagetime = asn1generalizedtime.getinstance(time);

        return this;
    }

    public pkiheaderbuilder setmessagetime(asn1generalizedtime time)
    {
        messagetime = time;

        return this;
    }

    public pkiheaderbuilder setprotectionalg(algorithmidentifier aid)
    {
        protectionalg = aid;

        return this;
    }

    public pkiheaderbuilder setsenderkid(byte[] kid)
    {
        return setsenderkid(kid == null ? null : new deroctetstring(kid));
    }

    public pkiheaderbuilder setsenderkid(asn1octetstring kid)
    {
        senderkid = kid;

        return this;
    }

    public pkiheaderbuilder setrecipkid(byte[] kid)
    {
        return setrecipkid(kid == null ? null : new deroctetstring(kid));
    }

    public pkiheaderbuilder setrecipkid(deroctetstring kid)
    {
        recipkid = kid;

        return this;
    }

    public pkiheaderbuilder settransactionid(byte[] tid)
    {
        return settransactionid(tid == null ? null : new deroctetstring(tid));
    }

    public pkiheaderbuilder settransactionid(asn1octetstring tid)
    {
        transactionid = tid;

        return this;
    }

    public pkiheaderbuilder setsendernonce(byte[] nonce)
    {
        return setsendernonce(nonce == null ? null : new deroctetstring(nonce));
    }

    public pkiheaderbuilder setsendernonce(asn1octetstring nonce)
    {
        sendernonce = nonce;

        return this;
    }

    public pkiheaderbuilder setrecipnonce(byte[] nonce)
    {
        return setrecipnonce(nonce == null ? null : new deroctetstring(nonce));
    }

    public pkiheaderbuilder setrecipnonce(asn1octetstring nonce)
    {
        recipnonce = nonce;

        return this;
    }

    public pkiheaderbuilder setfreetext(pkifreetext text)
    {
        freetext = text;

        return this;
    }

    public pkiheaderbuilder setgeneralinfo(infotypeandvalue geninfo)
    {
        return setgeneralinfo(makegeneralinfoseq(geninfo));
    }

    public pkiheaderbuilder setgeneralinfo(infotypeandvalue[] geninfos)
    {
        return setgeneralinfo(makegeneralinfoseq(geninfos));
    }

    public pkiheaderbuilder setgeneralinfo(asn1sequence seqofinfotypeandvalue)
    {
        generalinfo = seqofinfotypeandvalue;

        return this;
    }

    private static asn1sequence makegeneralinfoseq(
        infotypeandvalue generalinfo)
    {
        return new dersequence(generalinfo);
    }

    private static asn1sequence makegeneralinfoseq(
        infotypeandvalue[] generalinfos)
    {
        asn1sequence geninfoseq = null;
        if (generalinfos != null)
        {
            asn1encodablevector v = new asn1encodablevector();
            for (int i = 0; i < generalinfos.length; i++)
            {
                v.add(generalinfos[i]);
            }
            geninfoseq = new dersequence(v);
        }
        return geninfoseq;
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
     * @return a basic asn.1 object representation.
     */
    public pkiheader build()
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

        messagetime = null;
        protectionalg = null;
        senderkid = null;
        recipkid = null;
        transactionid = null;
        sendernonce = null;
        recipnonce = null;
        freetext = null;
        generalinfo = null;
        
        return pkiheader.getinstance(new dersequence(v));
    }

    private void addoptional(asn1encodablevector v, int tagno, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(new dertaggedobject(true, tagno, obj));
        }
    }
}
