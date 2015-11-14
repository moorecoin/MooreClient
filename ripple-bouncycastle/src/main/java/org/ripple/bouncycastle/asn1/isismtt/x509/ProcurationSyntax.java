package org.ripple.bouncycastle.asn1.isismtt.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.directorystring;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.issuerserial;

/**
 * attribute to indicate that the certificate holder may sign in the name of a
 * third person.
 * <p>
 * isis-mtt profile: the corresponding procurationsyntax contains either the
 * name of the person who is represented (subcomponent thirdperson) or a
 * reference to his/her base certificate (in the component signingfor,
 * subcomponent certref), furthermore the optional components country and
 * typesubstitution to indicate the country whose laws apply, and respectively
 * the type of procuration (e.g. manager, procuration, custody).
 * <p>
 * isis-mtt profile: the generalname must be of type directoryname and may only
 * contain: - rfc3039 attributes, except pseudonym (countryname, commonname,
 * surname, givenname, serialnumber, organizationname, organizationalunitname,
 * stateorprovincename, localityname, postaladdress) and - subjectdirectoryname
 * attributes (title, dateofbirth, placeofbirth, gender, countryofcitizenship,
 * countryofresidence and nameatbirth).
 * 
 * <pre>
 *               procurationsyntax ::= sequence {
 *                 country [1] explicit printablestring(size(2)) optional,
 *                 typeofsubstitution [2] explicit directorystring (size(1..128)) optional,
 *                 signingfor [3] explicit signingfor 
 *               }
 *               
 *               signingfor ::= choice 
 *               { 
 *                 thirdperson generalname,
 *                 certref issuerserial 
 *               }
 * </pre>
 * 
 */
public class procurationsyntax
    extends asn1object
{
    private string country;
    private directorystring typeofsubstitution;

    private generalname thirdperson;
    private issuerserial certref;

    public static procurationsyntax getinstance(object obj)
    {
        if (obj == null || obj instanceof procurationsyntax)
        {
            return (procurationsyntax)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new procurationsyntax((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * the sequence is of type procurationsyntax:
     * <p/>
     * <pre>
     *               procurationsyntax ::= sequence {
     *                 country [1] explicit printablestring(size(2)) optional,
     *                 typeofsubstitution [2] explicit directorystring (size(1..128)) optional,
     *                 signingfor [3] explicit signingfor
     *               }
     * <p/>
     *               signingfor ::= choice
     *               {
     *                 thirdperson generalname,
     *                 certref issuerserial
     *               }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private procurationsyntax(asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 3)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }
        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1taggedobject o = asn1taggedobject.getinstance(e.nextelement());
            switch (o.gettagno())
            {
                case 1:
                    country = derprintablestring.getinstance(o, true).getstring();
                    break;
                case 2:
                    typeofsubstitution = directorystring.getinstance(o, true);
                    break;
                case 3:
                    asn1encodable signingfor = o.getobject();
                    if (signingfor instanceof asn1taggedobject)
                    {
                        thirdperson = generalname.getinstance(signingfor);
                    }
                    else
                    {
                        certref = issuerserial.getinstance(signingfor);
                    }
                    break;
                default:
                    throw new illegalargumentexception("bad tag number: " + o.gettagno());
            }
        }
    }

    /**
     * constructor from a given details.
     * <p/>
     * <p/>
     * either <code>generalname</code> or <code>certref</code> must be
     * <code>null</code>.
     *
     * @param country            the country code whose laws apply.
     * @param typeofsubstitution the type of procuration.
     * @param certref            reference to certificate of the person who is represented.
     */
    public procurationsyntax(
        string country,
        directorystring typeofsubstitution,
        issuerserial certref)
    {
        this.country = country;
        this.typeofsubstitution = typeofsubstitution;
        this.thirdperson = null;
        this.certref = certref;
    }

    /**
     * constructor from a given details.
     * <p/>
     * <p/>
     * either <code>generalname</code> or <code>certref</code> must be
     * <code>null</code>.
     *
     * @param country            the country code whose laws apply.
     * @param typeofsubstitution the type of procuration.
     * @param thirdperson        the generalname of the person who is represented.
     */
    public procurationsyntax(
        string country,
        directorystring typeofsubstitution,
        generalname thirdperson)
    {
        this.country = country;
        this.typeofsubstitution = typeofsubstitution;
        this.thirdperson = thirdperson;
        this.certref = null;
    }

    public string getcountry()
    {
        return country;
    }

    public directorystring gettypeofsubstitution()
    {
        return typeofsubstitution;
    }

    public generalname getthirdperson()
    {
        return thirdperson;
    }

    public issuerserial getcertref()
    {
        return certref;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *               procurationsyntax ::= sequence {
     *                 country [1] explicit printablestring(size(2)) optional,
     *                 typeofsubstitution [2] explicit directorystring (size(1..128)) optional,
     *                 signingfor [3] explicit signingfor
     *               }
     * <p/>
     *               signingfor ::= choice
     *               {
     *                 thirdperson generalname,
     *                 certref issuerserial
     *               }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        if (country != null)
        {
            vec.add(new dertaggedobject(true, 1, new derprintablestring(country, true)));
        }
        if (typeofsubstitution != null)
        {
            vec.add(new dertaggedobject(true, 2, typeofsubstitution));
        }
        if (thirdperson != null)
        {
            vec.add(new dertaggedobject(true, 3, thirdperson));
        }
        else
        {
            vec.add(new dertaggedobject(true, 3, certref));
        }

        return new dersequence(vec);
    }
}
