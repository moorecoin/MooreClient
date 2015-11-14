package org.ripple.bouncycastle.asn1.isismtt.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.directorystring;

/**
 * professions, specializations, disciplines, fields of activity, etc.
 * 
 * <pre>
 *               professioninfo ::= sequence 
 *               {
 *                 namingauthority [0] explicit namingauthority optional,
 *                 professionitems sequence of directorystring (size(1..128)),
 *                 professionoids sequence of object identifier optional,
 *                 registrationnumber printablestring(size(1..128)) optional,
 *                 addprofessioninfo octet string optional 
 *               }
 * </pre>
 * 
 * @see org.ripple.bouncycastle.asn1.isismtt.x509.admissionsyntax
 */
public class professioninfo 
    extends asn1object
{

    /**
     * rechtsanw锟絣tin
     */
    public static final asn1objectidentifier rechtsanwltin = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".1");

    /**
     * rechtsanwalt
     */
    public static final asn1objectidentifier rechtsanwalt = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".2");

    /**
     * rechtsbeistand
     */
    public static final asn1objectidentifier rechtsbeistand = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".3");

    /**
     * steuerberaterin
     */
    public static final asn1objectidentifier steuerberaterin = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".4");

    /**
     * steuerberater
     */
    public static final asn1objectidentifier steuerberater = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".5");

    /**
     * steuerbevollm锟絚htigte
     */
    public static final asn1objectidentifier steuerbevollmchtigte = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".6");

    /**
     * steuerbevollm锟絚htigter
     */
    public static final asn1objectidentifier steuerbevollmchtigter = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".7");

    /**
     * notarin
     */
    public static final asn1objectidentifier notarin = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".8");

    /**
     * notar
     */
    public static final asn1objectidentifier notar = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".9");

    /**
     * notarvertreterin
     */
    public static final asn1objectidentifier notarvertreterin = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".10");

    /**
     * notarvertreter
     */
    public static final asn1objectidentifier notarvertreter = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".11");

    /**
     * notariatsverwalterin
     */
    public static final asn1objectidentifier notariatsverwalterin = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".12");

    /**
     * notariatsverwalter
     */
    public static final asn1objectidentifier notariatsverwalter = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".13");

    /**
     * wirtschaftspr锟絝erin
     */
    public static final asn1objectidentifier wirtschaftsprferin = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".14");

    /**
     * wirtschaftspr锟絝er
     */
    public static final asn1objectidentifier wirtschaftsprfer = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".15");

    /**
     * vereidigte buchpr锟絝erin
     */
    public static final asn1objectidentifier vereidigtebuchprferin = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".16");

    /**
     * vereidigter buchpr锟絝er
     */
    public static final asn1objectidentifier vereidigterbuchprfer = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".17");

    /**
     * patentanw锟絣tin
     */
    public static final asn1objectidentifier patentanwltin = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".18");

    /**
     * patentanwalt
     */
    public static final asn1objectidentifier patentanwalt = new asn1objectidentifier(
        namingauthority.id_isismtt_at_namingauthorities_rechtwirtschaftsteuern + ".19");

    private namingauthority namingauthority;

    private asn1sequence professionitems;

    private asn1sequence professionoids;

    private string registrationnumber;

    private asn1octetstring addprofessioninfo;

    public static professioninfo getinstance(object obj)
    {
        if (obj == null || obj instanceof professioninfo)
        {
            return (professioninfo)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new professioninfo((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * <p/>
     * <pre>
     *               professioninfo ::= sequence
     *               {
     *                 namingauthority [0] explicit namingauthority optional,
     *                 professionitems sequence of directorystring (size(1..128)),
     *                 professionoids sequence of object identifier optional,
     *                 registrationnumber printablestring(size(1..128)) optional,
     *                 addprofessioninfo octet string optional
     *               }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private professioninfo(asn1sequence seq)
    {
        if (seq.size() > 5)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }

        enumeration e = seq.getobjects();

        asn1encodable o = (asn1encodable)e.nextelement();

        if (o instanceof asn1taggedobject)
        {
            if (((asn1taggedobject)o).gettagno() != 0)
            {
                throw new illegalargumentexception("bad tag number: "
                    + ((asn1taggedobject)o).gettagno());
            }
            namingauthority = namingauthority.getinstance((asn1taggedobject)o, true);
            o = (asn1encodable)e.nextelement();
        }

        professionitems = asn1sequence.getinstance(o);

        if (e.hasmoreelements())
        {
            o = (asn1encodable)e.nextelement();
            if (o instanceof asn1sequence)
            {
                professionoids = asn1sequence.getinstance(o);
            }
            else if (o instanceof derprintablestring)
            {
                registrationnumber = derprintablestring.getinstance(o).getstring();
            }
            else if (o instanceof asn1octetstring)
            {
                addprofessioninfo = asn1octetstring.getinstance(o);
            }
            else
            {
                throw new illegalargumentexception("bad object encountered: "
                    + o.getclass());
            }
        }
        if (e.hasmoreelements())
        {
            o = (asn1encodable)e.nextelement();
            if (o instanceof derprintablestring)
            {
                registrationnumber = derprintablestring.getinstance(o).getstring();
            }
            else if (o instanceof deroctetstring)
            {
                addprofessioninfo = (deroctetstring)o;
            }
            else
            {
                throw new illegalargumentexception("bad object encountered: "
                    + o.getclass());
            }
        }
        if (e.hasmoreelements())
        {
            o = (asn1encodable)e.nextelement();
            if (o instanceof deroctetstring)
            {
                addprofessioninfo = (deroctetstring)o;
            }
            else
            {
                throw new illegalargumentexception("bad object encountered: "
                    + o.getclass());
            }
        }

    }

    /**
     * constructor from given details.
     * <p/>
     * <code>professionitems</code> is mandatory, all other parameters are
     * optional.
     *
     * @param namingauthority    the naming authority.
     * @param professionitems    directory strings of the profession.
     * @param professionoids     derobjectidentfier objects for the
     *                           profession.
     * @param registrationnumber registration number.
     * @param addprofessioninfo  additional infos in encoded form.
     */
    public professioninfo(namingauthority namingauthority,
                          directorystring[] professionitems, asn1objectidentifier[] professionoids,
                          string registrationnumber, asn1octetstring addprofessioninfo)
    {
        this.namingauthority = namingauthority;
        asn1encodablevector v = new asn1encodablevector();
        for (int i = 0; i != professionitems.length; i++)
        {
            v.add(professionitems[i]);
        }
        this.professionitems = new dersequence(v);
        if (professionoids != null)
        {
            v = new asn1encodablevector();
            for (int i = 0; i != professionoids.length; i++)
            {
                v.add(professionoids[i]);
            }
            this.professionoids = new dersequence(v);
        }
        this.registrationnumber = registrationnumber;
        this.addprofessioninfo = addprofessioninfo;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *               professioninfo ::= sequence
     *               {
     *                 namingauthority [0] explicit namingauthority optional,
     *                 professionitems sequence of directorystring (size(1..128)),
     *                 professionoids sequence of object identifier optional,
     *                 registrationnumber printablestring(size(1..128)) optional,
     *                 addprofessioninfo octet string optional
     *               }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        if (namingauthority != null)
        {
            vec.add(new dertaggedobject(true, 0, namingauthority));
        }
        vec.add(professionitems);
        if (professionoids != null)
        {
            vec.add(professionoids);
        }
        if (registrationnumber != null)
        {
            vec.add(new derprintablestring(registrationnumber, true));
        }
        if (addprofessioninfo != null)
        {
            vec.add(addprofessioninfo);
        }
        return new dersequence(vec);
    }

    /**
     * @return returns the addprofessioninfo.
     */
    public asn1octetstring getaddprofessioninfo()
    {
        return addprofessioninfo;
    }

    /**
     * @return returns the namingauthority.
     */
    public namingauthority getnamingauthority()
    {
        return namingauthority;
    }

    /**
     * @return returns the professionitems.
     */
    public directorystring[] getprofessionitems()
    {
        directorystring[] items = new directorystring[professionitems.size()];
        int count = 0;
        for (enumeration e = professionitems.getobjects(); e.hasmoreelements();)
        {
            items[count++] = directorystring.getinstance(e.nextelement());
        }
        return items;
    }

    /**
     * @return returns the professionoids.
     */
    public asn1objectidentifier[] getprofessionoids()
    {
        if (professionoids == null)
        {
            return new asn1objectidentifier[0];
        }
        asn1objectidentifier[] oids = new asn1objectidentifier[professionoids.size()];
        int count = 0;
        for (enumeration e = professionoids.getobjects(); e.hasmoreelements();)
        {
            oids[count++] = asn1objectidentifier.getinstance(e.nextelement());
        }
        return oids;
    }

    /**
     * @return returns the registrationnumber.
     */
    public string getregistrationnumber()
    {
        return registrationnumber;
    }
}
