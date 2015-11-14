package org.ripple.bouncycastle.asn1.x500.style;

import java.io.ioexception;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.derutf8string;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x500.attributetypeandvalue;
import org.ripple.bouncycastle.asn1.x500.rdn;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x500.x500namestyle;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;

public class bcstyle
    implements x500namestyle
{
    public static final x500namestyle instance = new bcstyle();

    /**
     * country code - stringtype(size(2))
     */
    public static final asn1objectidentifier c = new asn1objectidentifier("2.5.4.6");

    /**
     * organization - stringtype(size(1..64))
     */
    public static final asn1objectidentifier o = new asn1objectidentifier("2.5.4.10");

    /**
     * organizational unit name - stringtype(size(1..64))
     */
    public static final asn1objectidentifier ou = new asn1objectidentifier("2.5.4.11");

    /**
     * title
     */
    public static final asn1objectidentifier t = new asn1objectidentifier("2.5.4.12");

    /**
     * common name - stringtype(size(1..64))
     */
    public static final asn1objectidentifier cn = new asn1objectidentifier("2.5.4.3");

    /**
     * device serial number name - stringtype(size(1..64))
     */
    public static final asn1objectidentifier sn = new asn1objectidentifier("2.5.4.5");

    /**
     * street - stringtype(size(1..64))
     */
    public static final asn1objectidentifier street = new asn1objectidentifier("2.5.4.9");

    /**
     * device serial number name - stringtype(size(1..64))
     */
    public static final asn1objectidentifier serialnumber = sn;

    /**
     * locality name - stringtype(size(1..64))
     */
    public static final asn1objectidentifier l = new asn1objectidentifier("2.5.4.7");

    /**
     * state, or province name - stringtype(size(1..64))
     */
    public static final asn1objectidentifier st = new asn1objectidentifier("2.5.4.8");

    /**
     * naming attributes of type x520name
     */
    public static final asn1objectidentifier surname = new asn1objectidentifier("2.5.4.4");
    public static final asn1objectidentifier givenname = new asn1objectidentifier("2.5.4.42");
    public static final asn1objectidentifier initials = new asn1objectidentifier("2.5.4.43");
    public static final asn1objectidentifier generation = new asn1objectidentifier("2.5.4.44");
    public static final asn1objectidentifier unique_identifier = new asn1objectidentifier("2.5.4.45");

    /**
     * businesscategory - directorystring(size(1..128)
     */
    public static final asn1objectidentifier business_category = new asn1objectidentifier(
        "2.5.4.15");

    /**
     * postalcode - directorystring(size(1..40)
     */
    public static final asn1objectidentifier postal_code = new asn1objectidentifier(
        "2.5.4.17");

    /**
     * dnqualifier - directorystring(size(1..64)
     */
    public static final asn1objectidentifier dn_qualifier = new asn1objectidentifier(
        "2.5.4.46");

    /**
     * rfc 3039 pseudonym - directorystring(size(1..64)
     */
    public static final asn1objectidentifier pseudonym = new asn1objectidentifier(
        "2.5.4.65");


    /**
     * rfc 3039 dateofbirth - generalizedtime - yyyymmdd000000z
     */
    public static final asn1objectidentifier date_of_birth = new asn1objectidentifier(
        "1.3.6.1.5.5.7.9.1");

    /**
     * rfc 3039 placeofbirth - directorystring(size(1..128)
     */
    public static final asn1objectidentifier place_of_birth = new asn1objectidentifier(
        "1.3.6.1.5.5.7.9.2");

    /**
     * rfc 3039 gender - printablestring (size(1)) -- "m", "f", "m" or "f"
     */
    public static final asn1objectidentifier gender = new asn1objectidentifier(
        "1.3.6.1.5.5.7.9.3");

    /**
     * rfc 3039 countryofcitizenship - printablestring (size (2)) -- iso 3166
     * codes only
     */
    public static final asn1objectidentifier country_of_citizenship = new asn1objectidentifier(
        "1.3.6.1.5.5.7.9.4");

    /**
     * rfc 3039 countryofresidence - printablestring (size (2)) -- iso 3166
     * codes only
     */
    public static final asn1objectidentifier country_of_residence = new asn1objectidentifier(
        "1.3.6.1.5.5.7.9.5");


    /**
     * isis-mtt nameatbirth - directorystring(size(1..64)
     */
    public static final asn1objectidentifier name_at_birth = new asn1objectidentifier("1.3.36.8.3.14");

    /**
     * rfc 3039 postaladdress - sequence size (1..6) of
     * directorystring(size(1..30))
     */
    public static final asn1objectidentifier postal_address = new asn1objectidentifier("2.5.4.16");

    /**
     * rfc 2256 dmdname
     */
    public static final asn1objectidentifier dmd_name = new asn1objectidentifier("2.5.4.54");

    /**
     * id-at-telephonenumber
     */
    public static final asn1objectidentifier telephone_number = x509objectidentifiers.id_at_telephonenumber;

    /**
     * id-at-name
     */
    public static final asn1objectidentifier name = x509objectidentifiers.id_at_name;

    /**
     * email address (rsa pkcs#9 extension) - ia5string.
     * <p>note: if you're trying to be ultra orthodox, don't use this! it shouldn't be in here.
     */
    public static final asn1objectidentifier emailaddress = pkcsobjectidentifiers.pkcs_9_at_emailaddress;

    /**
     * more from pkcs#9
     */
    public static final asn1objectidentifier unstructuredname = pkcsobjectidentifiers.pkcs_9_at_unstructuredname;
    public static final asn1objectidentifier unstructuredaddress = pkcsobjectidentifiers.pkcs_9_at_unstructuredaddress;

    /**
     * email address in verisign certificates
     */
    public static final asn1objectidentifier e = emailaddress;

    /*
    * others...
    */
    public static final asn1objectidentifier dc = new asn1objectidentifier("0.9.2342.19200300.100.1.25");

    /**
     * ldap user id.
     */
    public static final asn1objectidentifier uid = new asn1objectidentifier("0.9.2342.19200300.100.1.1");

    /**
     * default look up table translating oid values into their common symbols following
     * the convention in rfc 2253 with a few extras
     */
    private static final hashtable defaultsymbols = new hashtable();

    /**
     * look up table translating common symbols into their oids.
     */
    private static final hashtable defaultlookup = new hashtable();

    static
    {
        defaultsymbols.put(c, "c");
        defaultsymbols.put(o, "o");
        defaultsymbols.put(t, "t");
        defaultsymbols.put(ou, "ou");
        defaultsymbols.put(cn, "cn");
        defaultsymbols.put(l, "l");
        defaultsymbols.put(st, "st");
        defaultsymbols.put(sn, "serialnumber");
        defaultsymbols.put(emailaddress, "e");
        defaultsymbols.put(dc, "dc");
        defaultsymbols.put(uid, "uid");
        defaultsymbols.put(street, "street");
        defaultsymbols.put(surname, "surname");
        defaultsymbols.put(givenname, "givenname");
        defaultsymbols.put(initials, "initials");
        defaultsymbols.put(generation, "generation");
        defaultsymbols.put(unstructuredaddress, "unstructuredaddress");
        defaultsymbols.put(unstructuredname, "unstructuredname");
        defaultsymbols.put(unique_identifier, "uniqueidentifier");
        defaultsymbols.put(dn_qualifier, "dn");
        defaultsymbols.put(pseudonym, "pseudonym");
        defaultsymbols.put(postal_address, "postaladdress");
        defaultsymbols.put(name_at_birth, "nameatbirth");
        defaultsymbols.put(country_of_citizenship, "countryofcitizenship");
        defaultsymbols.put(country_of_residence, "countryofresidence");
        defaultsymbols.put(gender, "gender");
        defaultsymbols.put(place_of_birth, "placeofbirth");
        defaultsymbols.put(date_of_birth, "dateofbirth");
        defaultsymbols.put(postal_code, "postalcode");
        defaultsymbols.put(business_category, "businesscategory");
        defaultsymbols.put(telephone_number, "telephonenumber");
        defaultsymbols.put(name, "name");

        defaultlookup.put("c", c);
        defaultlookup.put("o", o);
        defaultlookup.put("t", t);
        defaultlookup.put("ou", ou);
        defaultlookup.put("cn", cn);
        defaultlookup.put("l", l);
        defaultlookup.put("st", st);
        defaultlookup.put("sn", sn);
        defaultlookup.put("serialnumber", sn);
        defaultlookup.put("street", street);
        defaultlookup.put("emailaddress", e);
        defaultlookup.put("dc", dc);
        defaultlookup.put("e", e);
        defaultlookup.put("uid", uid);
        defaultlookup.put("surname", surname);
        defaultlookup.put("givenname", givenname);
        defaultlookup.put("initials", initials);
        defaultlookup.put("generation", generation);
        defaultlookup.put("unstructuredaddress", unstructuredaddress);
        defaultlookup.put("unstructuredname", unstructuredname);
        defaultlookup.put("uniqueidentifier", unique_identifier);
        defaultlookup.put("dn", dn_qualifier);
        defaultlookup.put("pseudonym", pseudonym);
        defaultlookup.put("postaladdress", postal_address);
        defaultlookup.put("nameofbirth", name_at_birth);
        defaultlookup.put("countryofcitizenship", country_of_citizenship);
        defaultlookup.put("countryofresidence", country_of_residence);
        defaultlookup.put("gender", gender);
        defaultlookup.put("placeofbirth", place_of_birth);
        defaultlookup.put("dateofbirth", date_of_birth);
        defaultlookup.put("postalcode", postal_code);
        defaultlookup.put("businesscategory", business_category);
        defaultlookup.put("telephonenumber", telephone_number);
        defaultlookup.put("name", name);
    }

    protected bcstyle()
    {

    }
    
    public asn1encodable stringtovalue(asn1objectidentifier oid, string value)
    {
        if (value.length() != 0 && value.charat(0) == '#')
        {
            try
            {
                return ietfutils.valuefromhexstring(value, 1);
            }
            catch (ioexception e)
            {
                throw new runtimeexception("can't recode value for oid " + oid.getid());
            }
        }
        else
        {
            if (value.length() != 0 && value.charat(0) == '\\')
            {
                value = value.substring(1);
            }
            if (oid.equals(emailaddress) || oid.equals(dc))
            {
                return new deria5string(value);
            }
            else if (oid.equals(date_of_birth))  // accept time string as well as # (for compatibility)
            {
                return new asn1generalizedtime(value);
            }
            else if (oid.equals(c) || oid.equals(sn) || oid.equals(dn_qualifier)
                || oid.equals(telephone_number))
            {
                return new derprintablestring(value);
            }
        }

        return new derutf8string(value);
    }

    public string oidtodisplayname(asn1objectidentifier oid)
    {
        return (string)defaultsymbols.get(oid);
    }

    public string[] oidtoattrnames(asn1objectidentifier oid)
    {
        return ietfutils.findattrnamesforoid(oid, defaultlookup);
    }

    public asn1objectidentifier attrnametooid(string attrname)
    {
        return ietfutils.decodeattrname(attrname, defaultlookup);
    }

    public boolean areequal(x500name name1, x500name name2)
    {
        rdn[] rdns1 = name1.getrdns();
        rdn[] rdns2 = name2.getrdns();

        if (rdns1.length != rdns2.length)
        {
            return false;
        }

        boolean reverse = false;

        if (rdns1[0].getfirst() != null && rdns2[0].getfirst() != null)
        {
            reverse = !rdns1[0].getfirst().gettype().equals(rdns2[0].getfirst().gettype());  // guess forward
        }

        for (int i = 0; i != rdns1.length; i++)
        {
            if (!foundmatch(reverse, rdns1[i], rdns2))
            {
                return false;
            }
        }

        return true;
    }

    private boolean foundmatch(boolean reverse, rdn rdn, rdn[] possrdns)
    {
        if (reverse)
        {
            for (int i = possrdns.length - 1; i >= 0; i--)
            {
                if (possrdns[i] != null && rdnareequal(rdn, possrdns[i]))
                {
                    possrdns[i] = null;
                    return true;
                }
            }
        }
        else
        {
            for (int i = 0; i != possrdns.length; i++)
            {
                if (possrdns[i] != null && rdnareequal(rdn, possrdns[i]))
                {
                    possrdns[i] = null;
                    return true;
                }
            }
        }

        return false;
    }

    protected boolean rdnareequal(rdn rdn1, rdn rdn2)
    {
        return ietfutils.rdnareequal(rdn1, rdn2);
    }

    public rdn[] fromstring(string dirname)
    {
        return ietfutils.rdnsfromstring(dirname, this);
    }

    public int calculatehashcode(x500name name)
    {
        int hashcodevalue = 0;
        rdn[] rdns = name.getrdns();

        // this needs to be order independent, like equals
        for (int i = 0; i != rdns.length; i++)
        {
            if (rdns[i].ismultivalued())
            {
                attributetypeandvalue[] atv = rdns[i].gettypesandvalues();

                for (int j = 0; j != atv.length; j++)
                {
                    hashcodevalue ^= atv[j].gettype().hashcode();
                    hashcodevalue ^= calchashcode(atv[j].getvalue());
                }
            }
            else
            {
                hashcodevalue ^= rdns[i].getfirst().gettype().hashcode();
                hashcodevalue ^= calchashcode(rdns[i].getfirst().getvalue());
            }
        }

        return hashcodevalue;
    }

    private int calchashcode(asn1encodable enc)
    {
        string value = ietfutils.valuetostring(enc);

        value = ietfutils.canonicalize(value);

        return value.hashcode();
    }

    public string tostring(x500name name)
    {
        stringbuffer buf = new stringbuffer();
        boolean first = true;

        rdn[] rdns = name.getrdns();

        for (int i = 0; i < rdns.length; i++)
        {
            if (first)
            {
                first = false;
            }
            else
            {
                buf.append(',');
            }

            ietfutils.appendrdn(buf, rdns[i], defaultsymbols);
        }

        return buf.tostring();
    }
}
