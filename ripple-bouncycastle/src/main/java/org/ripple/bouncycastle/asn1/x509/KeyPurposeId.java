package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;

/**
 * the keypurposeid object.
 * <pre>
 *     keypurposeid ::= object identifier
 *
 *     id-kp ::= object identifier { iso(1) identified-organization(3) 
 *          dod(6) internet(1) security(5) mechanisms(5) pkix(7) 3}
 *
 * </pre>
 * to create a new keypurposeid where none of the below suit, use
 * <pre>
 *     asn1objectidentifier newkeypurposeidoid = new asn1objectidentifier("1.3.6.1...");
 *
 *     keypurposeid newkeypurposeid = keypurposeid.getinstance(newkeypurposeidoid);
 * </pre>
 */
public class keypurposeid
    extends asn1object
{
    private static final asn1objectidentifier id_kp = new asn1objectidentifier("1.3.6.1.5.5.7.3");

    /**
     * { 2 5 29 37 0 }
     */
    public static final keypurposeid anyextendedkeyusage = new keypurposeid(extension.extendedkeyusage.branch("0"));

    /**
     * { id-kp 1 }
     */
    public static final keypurposeid id_kp_serverauth = new keypurposeid(id_kp.branch("1"));
    /**
     * { id-kp 2 }
     */
    public static final keypurposeid id_kp_clientauth = new keypurposeid(id_kp.branch("2"));
    /**
     * { id-kp 3 }
     */
    public static final keypurposeid id_kp_codesigning = new keypurposeid(id_kp.branch("3"));
    /**
     * { id-kp 4 }
     */
    public static final keypurposeid id_kp_emailprotection = new keypurposeid(id_kp.branch("4"));
    /**
     * usage deprecated by rfc4945 - was { id-kp 5 }
     */
    public static final keypurposeid id_kp_ipsecendsystem = new keypurposeid(id_kp.branch("5"));
    /**
     * usage deprecated by rfc4945 - was { id-kp 6 }
     */
    public static final keypurposeid id_kp_ipsectunnel = new keypurposeid(id_kp.branch("6"));
    /**
     * usage deprecated by rfc4945 - was { idkp 7 }
     */
    public static final keypurposeid id_kp_ipsecuser = new keypurposeid(id_kp.branch("7"));
    /**
     * { id-kp 8 }
     */
    public static final keypurposeid id_kp_timestamping = new keypurposeid(id_kp.branch("8"));
    /**
     * { id-kp 9 }
     */
    public static final keypurposeid id_kp_ocspsigning = new keypurposeid(id_kp.branch("9"));
    /**
     * { id-kp 10 }
     */
    public static final keypurposeid id_kp_dvcs = new keypurposeid(id_kp.branch("10"));
    /**
     * { id-kp 11 }
     */
    public static final keypurposeid id_kp_sbgpcertaaserverauth = new keypurposeid(id_kp.branch("11"));
    /**
     * { id-kp 12 }
     */
    public static final keypurposeid id_kp_scvp_responder = new keypurposeid(id_kp.branch("12"));
    /**
     * { id-kp 13 }
     */
    public static final keypurposeid id_kp_eapoverppp = new keypurposeid(id_kp.branch("13"));
    /**
     * { id-kp 14 }
     */
    public static final keypurposeid id_kp_eapoverlan = new keypurposeid(id_kp.branch("14"));
    /**
     * { id-kp 15 }
     */
    public static final keypurposeid id_kp_scvpserver = new keypurposeid(id_kp.branch("15"));
    /**
     * { id-kp 16 }
     */
    public static final keypurposeid id_kp_scvpclient = new keypurposeid(id_kp.branch("16"));
    /**
     * { id-kp 17 }
     */
    public static final keypurposeid id_kp_ipsecike = new keypurposeid(id_kp.branch("17"));
    /**
     * { id-kp 18 }
     */
    public static final keypurposeid id_kp_capwapac = new keypurposeid(id_kp.branch("18"));
    /**
     * { id-kp 19 }
     */
    public static final keypurposeid id_kp_capwapwtp = new keypurposeid(id_kp.branch("19"));

    //
    // microsoft key purpose ids
    //
    /**
     * { 1 3 6 1 4 1 311 20 2 2 }
     */
    public static final keypurposeid id_kp_smartcardlogon = new keypurposeid(new asn1objectidentifier("1.3.6.1.4.1.311.20.2.2"));

    private asn1objectidentifier id;

    private keypurposeid(asn1objectidentifier id)
    {
        this.id = id;
    }

    /**
     * @deprecated use getinstance and an oid or one of the constants above.
     * @param id string representation of an oid.
     */
    public keypurposeid(string id)
    {
        this(new asn1objectidentifier(id));
    }

    public static keypurposeid getinstance(object o)
    {
        if (o instanceof keypurposeid)
        {
            return (keypurposeid)o;
        }
        else if (o != null)
        {
            return new keypurposeid(asn1objectidentifier.getinstance(o));
        }

        return null;
    }

    public asn1primitive toasn1primitive()
    {
        return id;
    }

    public string getid()
    {
        return id.getid();
    }
}
