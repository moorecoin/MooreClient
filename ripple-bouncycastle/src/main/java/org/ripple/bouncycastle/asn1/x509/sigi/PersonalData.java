package org.ripple.bouncycastle.asn1.x509.sigi;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.directorystring;

/**
 * contains personal data for the othername field in the subjectaltnames
 * extension.
 * <p/>
 * <pre>
 *     personaldata ::= sequence {
 *       nameorpseudonym nameorpseudonym,
 *       namedistinguisher [0] integer optional,
 *       dateofbirth [1] generalizedtime optional,
 *       placeofbirth [2] directorystring optional,
 *       gender [3] printablestring optional,
 *       postaladdress [4] directorystring optional
 *       }
 * </pre>
 *
 * @see org.ripple.bouncycastle.asn1.x509.sigi.nameorpseudonym
 * @see org.ripple.bouncycastle.asn1.x509.sigi.sigiobjectidentifiers
 */
public class personaldata
    extends asn1object
{
    private nameorpseudonym nameorpseudonym;
    private biginteger namedistinguisher;
    private asn1generalizedtime dateofbirth;
    private directorystring placeofbirth;
    private string gender;
    private directorystring postaladdress;

    public static personaldata getinstance(object obj)
    {
        if (obj == null || obj instanceof personaldata)
        {
            return (personaldata)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new personaldata((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * the sequence is of type nameorpseudonym:
     * <p/>
     * <pre>
     *     personaldata ::= sequence {
     *       nameorpseudonym nameorpseudonym,
     *       namedistinguisher [0] integer optional,
     *       dateofbirth [1] generalizedtime optional,
     *       placeofbirth [2] directorystring optional,
     *       gender [3] printablestring optional,
     *       postaladdress [4] directorystring optional
     *       }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private personaldata(asn1sequence seq)
    {
        if (seq.size() < 1)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }

        enumeration e = seq.getobjects();

        nameorpseudonym = nameorpseudonym.getinstance(e.nextelement());

        while (e.hasmoreelements())
        {
            asn1taggedobject o = asn1taggedobject.getinstance(e.nextelement());
            int tag = o.gettagno();
            switch (tag)
            {
                case 0:
                    namedistinguisher = asn1integer.getinstance(o, false).getvalue();
                    break;
                case 1:
                    dateofbirth = asn1generalizedtime.getinstance(o, false);
                    break;
                case 2:
                    placeofbirth = directorystring.getinstance(o, true);
                    break;
                case 3:
                    gender = derprintablestring.getinstance(o, false).getstring();
                    break;
                case 4:
                    postaladdress = directorystring.getinstance(o, true);
                    break;
                default:
                    throw new illegalargumentexception("bad tag number: " + o.gettagno());
            }
        }
    }

    /**
     * constructor from a given details.
     *
     * @param nameorpseudonym   name or pseudonym.
     * @param namedistinguisher name distinguisher.
     * @param dateofbirth       date of birth.
     * @param placeofbirth      place of birth.
     * @param gender            gender.
     * @param postaladdress     postal address.
     */
    public personaldata(nameorpseudonym nameorpseudonym,
                        biginteger namedistinguisher, asn1generalizedtime dateofbirth,
                        directorystring placeofbirth, string gender, directorystring postaladdress)
    {
        this.nameorpseudonym = nameorpseudonym;
        this.dateofbirth = dateofbirth;
        this.gender = gender;
        this.namedistinguisher = namedistinguisher;
        this.postaladdress = postaladdress;
        this.placeofbirth = placeofbirth;
    }

    public nameorpseudonym getnameorpseudonym()
    {
        return nameorpseudonym;
    }

    public biginteger getnamedistinguisher()
    {
        return namedistinguisher;
    }

    public asn1generalizedtime getdateofbirth()
    {
        return dateofbirth;
    }

    public directorystring getplaceofbirth()
    {
        return placeofbirth;
    }

    public string getgender()
    {
        return gender;
    }

    public directorystring getpostaladdress()
    {
        return postaladdress;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *     personaldata ::= sequence {
     *       nameorpseudonym nameorpseudonym,
     *       namedistinguisher [0] integer optional,
     *       dateofbirth [1] generalizedtime optional,
     *       placeofbirth [2] directorystring optional,
     *       gender [3] printablestring optional,
     *       postaladdress [4] directorystring optional
     *       }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        vec.add(nameorpseudonym);
        if (namedistinguisher != null)
        {
            vec.add(new dertaggedobject(false, 0, new asn1integer(namedistinguisher)));
        }
        if (dateofbirth != null)
        {
            vec.add(new dertaggedobject(false, 1, dateofbirth));
        }
        if (placeofbirth != null)
        {
            vec.add(new dertaggedobject(true, 2, placeofbirth));
        }
        if (gender != null)
        {
            vec.add(new dertaggedobject(false, 3, new derprintablestring(gender, true)));
        }
        if (postaladdress != null)
        {
            vec.add(new dertaggedobject(true, 4, postaladdress));
        }
        return new dersequence(vec);
    }
}
