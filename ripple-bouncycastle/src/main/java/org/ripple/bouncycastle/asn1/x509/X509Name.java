package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;
import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derset;
import org.ripple.bouncycastle.asn1.deruniversalstring;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.util.strings;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * <pre>
 *     rdnsequence ::= sequence of relativedistinguishedname
 *
 *     relativedistinguishedname ::= set size (1..max) of attributetypeandvalue
 *
 *     attributetypeandvalue ::= sequence {
 *                                   type  object identifier,
 *                                   value any }
 * </pre>
 * @deprecated use org.bouncycastle.asn1.x500.x500name.
 */
public class x509name
    extends asn1object
{
    /**
     * country code - stringtype(size(2))
     * @deprecated use a x500namestyle
     */
    public static final asn1objectidentifier c = new asn1objectidentifier("2.5.4.6");

    /**
     * organization - stringtype(size(1..64))
     * @deprecated use a x500namestyle
     */
    public static final asn1objectidentifier o = new asn1objectidentifier("2.5.4.10");

    /**
     * organizational unit name - stringtype(size(1..64))
     * @deprecated use a x500namestyle
     */
    public static final asn1objectidentifier ou = new asn1objectidentifier("2.5.4.11");

    /**
     * title
     * @deprecated use a x500namestyle
     */
    public static final asn1objectidentifier t = new asn1objectidentifier("2.5.4.12");

    /**
     * common name - stringtype(size(1..64))
     * @deprecated use a x500namestyle
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
    public static final asn1objectidentifier name_at_birth =  new asn1objectidentifier("1.3.36.8.3.14");

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
     * @deprecated use a x500namestyle
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
     * determines whether or not strings should be processed and printed
     * from back to front.
     */
    public static boolean defaultreverse = false;

    /**
     * default look up table translating oid values into their common symbols following
     * the convention in rfc 2253 with a few extras
     */
    public static final hashtable defaultsymbols = new hashtable();

    /**
     * look up table translating oid values into their common symbols following the convention in rfc 2253
     * 
     */
    public static final hashtable rfc2253symbols = new hashtable();

    /**
     * look up table translating oid values into their common symbols following the convention in rfc 1779
     * 
     */
    public static final hashtable rfc1779symbols = new hashtable();

    /**
     * look up table translating common symbols into their oids.
     */
    public static final hashtable defaultlookup = new hashtable();

    /**
     * look up table translating oid values into their common symbols
     * @deprecated use defaultsymbols
     */
    public static final hashtable oidlookup = defaultsymbols;

    /**
     * look up table translating string values into their oids -
     * @deprecated use defaultlookup
     */
    public static final hashtable symbollookup = defaultlookup;

    private static final boolean true = new boolean(true); // for j2me compatibility
    private static final boolean false = new boolean(false);

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

        rfc2253symbols.put(c, "c");
        rfc2253symbols.put(o, "o");
        rfc2253symbols.put(ou, "ou");
        rfc2253symbols.put(cn, "cn");
        rfc2253symbols.put(l, "l");
        rfc2253symbols.put(st, "st");
        rfc2253symbols.put(street, "street");
        rfc2253symbols.put(dc, "dc");
        rfc2253symbols.put(uid, "uid");

        rfc1779symbols.put(c, "c");
        rfc1779symbols.put(o, "o");
        rfc1779symbols.put(ou, "ou");
        rfc1779symbols.put(cn, "cn");
        rfc1779symbols.put(l, "l");
        rfc1779symbols.put(st, "st");
        rfc1779symbols.put(street, "street");

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

    private x509nameentryconverter  converter = null;
    private vector                  ordering = new vector();
    private vector                  values = new vector();
    private vector                  added = new vector();

    private asn1sequence            seq;

    private boolean                 ishashcodecalculated;
    private int                     hashcodevalue;

    /**
     * return a x509name based on the passed in tagged object.
     * 
     * @param obj tag object holding name.
     * @param explicit true if explicitly tagged false otherwise.
     * @return the x509name
     */
    public static x509name getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static x509name getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof x509name)
        {
            return (x509name)obj;
        }
        else if (obj instanceof x500name)
        {
            return new x509name(asn1sequence.getinstance(((x500name)obj).toasn1primitive()));
        }
        else if (obj != null)
        {
            return new x509name(asn1sequence.getinstance(obj));
        }

        return null;
    }

    protected x509name()
    {
        // constructure use by new x500 name class
    }
    /**
     * constructor from asn1sequence
     *
     * the principal will be a list of constructed sets, each containing an (oid, string) pair.
     * @deprecated use x500name.getinstance()
     */
    public x509name(
        asn1sequence  seq)
    {
        this.seq = seq;

        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1set         set = asn1set.getinstance(((asn1encodable)e.nextelement()).toasn1primitive());

            for (int i = 0; i < set.size(); i++) 
            {
                   asn1sequence s = asn1sequence.getinstance(set.getobjectat(i).toasn1primitive());

                   if (s.size() != 2)
                   {
                       throw new illegalargumentexception("badly sized pair");
                   }

                   ordering.addelement(asn1objectidentifier.getinstance(s.getobjectat(0)));
                   
                   asn1encodable value = s.getobjectat(1);
                   if (value instanceof asn1string && !(value instanceof deruniversalstring))
                   {
                       string v = ((asn1string)value).getstring();
                       if (v.length() > 0 && v.charat(0) == '#')
                       {
                           values.addelement("\\" + v);
                       }
                       else
                       {
                           values.addelement(v);
                       }
                   }
                   else
                   {
                       try
                       {
                           values.addelement("#" + bytestostring(hex.encode(value.toasn1primitive().getencoded(asn1encoding.der))));
                       }
                       catch (ioexception e1)
                       {
                           throw new illegalargumentexception("cannot encode value");
                       }
                   }
                   added.addelement((i != 0) ? true : false);  // to allow earlier jdk compatibility
            }
        }
    }

    /**
     * constructor from a table of attributes.
     * <p>
     * it's is assumed the table contains oid/string pairs, and the contents
     * of the table are copied into an internal table as part of the
     * construction process.
     * <p>
     * <b>note:</b> if the name you are trying to generate should be
     * following a specific ordering, you should use the constructor
     * with the ordering specified below.
     * @deprecated use an ordered constructor! the hashtable ordering is rarely correct
     */
    public x509name(
        hashtable  attributes)
    {
        this(null, attributes);
    }

    /**
     * constructor from a table of attributes with ordering.
     * <p>
     * it's is assumed the table contains oid/string pairs, and the contents
     * of the table are copied into an internal table as part of the
     * construction process. the ordering vector should contain the oids
     * in the order they are meant to be encoded or printed in tostring.
     */
    public x509name(
        vector      ordering,
        hashtable   attributes)
    {
        this(ordering, attributes, new x509defaultentryconverter());
    }

    /**
     * constructor from a table of attributes with ordering.
     * <p>
     * it's is assumed the table contains oid/string pairs, and the contents
     * of the table are copied into an internal table as part of the
     * construction process. the ordering vector should contain the oids
     * in the order they are meant to be encoded or printed in tostring.
     * <p>
     * the passed in converter will be used to convert the strings into their
     * asn.1 counterparts.
     * @deprecated use x500name, x500namebuilder
     */
    public x509name(
        vector                   ordering,
        hashtable                attributes,
        x509nameentryconverter   converter)
    {
        this.converter = converter;

        if (ordering != null)
        {
            for (int i = 0; i != ordering.size(); i++)
            {
                this.ordering.addelement(ordering.elementat(i));
                this.added.addelement(false);
            }
        }
        else
        {
            enumeration     e = attributes.keys();

            while (e.hasmoreelements())
            {
                this.ordering.addelement(e.nextelement());
                this.added.addelement(false);
            }
        }

        for (int i = 0; i != this.ordering.size(); i++)
        {
            asn1objectidentifier     oid = (asn1objectidentifier)this.ordering.elementat(i);

            if (attributes.get(oid) == null)
            {
                throw new illegalargumentexception("no attribute for object id - " + oid.getid() + " - passed to distinguished name");
            }

            this.values.addelement(attributes.get(oid)); // copy the hash table
        }
    }

    /**
     * takes two vectors one of the oids and the other of the values.
     * @deprecated use x500name, x500namebuilder
     */
    public x509name(
        vector  oids,
        vector  values)
    {
        this(oids, values, new x509defaultentryconverter());
    }

    /**
     * takes two vectors one of the oids and the other of the values.
     * <p>
     * the passed in converter will be used to convert the strings into their
     * asn.1 counterparts.
     * @deprecated use x500name, x500namebuilder
     */
    public x509name(
        vector                  oids,
        vector                  values,
        x509nameentryconverter  converter)
    {
        this.converter = converter;

        if (oids.size() != values.size())
        {
            throw new illegalargumentexception("oids vector must be same length as values.");
        }

        for (int i = 0; i < oids.size(); i++)
        {
            this.ordering.addelement(oids.elementat(i));
            this.values.addelement(values.elementat(i));
            this.added.addelement(false);
        }
    }

//    private boolean isencoded(string s)
//    {
//        if (s.charat(0) == '#')
//        {
//            return true;
//        }
//
//        return false;
//    }

    /**
     * takes an x509 dir name as a string of the format "c=au, st=victoria", or
     * some such, converting it into an ordered set of name attributes.
     * @deprecated use x500name, x500namebuilder
     */
    public x509name(
        string  dirname)
    {
        this(defaultreverse, defaultlookup, dirname);
    }

    /**
     * takes an x509 dir name as a string of the format "c=au, st=victoria", or
     * some such, converting it into an ordered set of name attributes with each
     * string value being converted to its associated asn.1 type using the passed
     * in converter.
     * @deprecated use x500name, x500namebuilder
     */
    public x509name(
        string                  dirname,
        x509nameentryconverter  converter)
    {
        this(defaultreverse, defaultlookup, dirname, converter);
    }

    /**
     * takes an x509 dir name as a string of the format "c=au, st=victoria", or
     * some such, converting it into an ordered set of name attributes. if reverse
     * is true, create the encoded version of the sequence starting from the
     * last element in the string.
     * @deprecated use x500name, x500namebuilder
     */
    public x509name(
        boolean reverse,
        string  dirname)
    {
        this(reverse, defaultlookup, dirname);
    }

    /**
     * takes an x509 dir name as a string of the format "c=au, st=victoria", or
     * some such, converting it into an ordered set of name attributes with each
     * string value being converted to its associated asn.1 type using the passed
     * in converter. if reverse is true the asn.1 sequence representing the dn will
     * be built by starting at the end of the string, rather than the start.
     * @deprecated use x500name, x500namebuilder
     */
    public x509name(
        boolean                 reverse,
        string                  dirname,
        x509nameentryconverter  converter)
    {
        this(reverse, defaultlookup, dirname, converter);
    }

    /**
     * takes an x509 dir name as a string of the format "c=au, st=victoria", or
     * some such, converting it into an ordered set of name attributes. lookup
     * should provide a table of lookups, indexed by lowercase only strings and
     * yielding a asn1objectidentifier, other than that oid. and numeric oids
     * will be processed automatically.
     * <br>
     * if reverse is true, create the encoded version of the sequence
     * starting from the last element in the string.
     * @param reverse true if we should start scanning from the end (rfc 2553).
     * @param lookup table of names and their oids.
     * @param dirname the x.500 string to be parsed.
     * @deprecated use x500name, x500namebuilder
     */
    public x509name(
        boolean     reverse,
        hashtable   lookup,
        string      dirname)
    {
        this(reverse, lookup, dirname, new x509defaultentryconverter());
    }

    private asn1objectidentifier decodeoid(
        string      name,
        hashtable   lookup)
    {
        name = name.trim();
        if (strings.touppercase(name).startswith("oid."))
        {
            return new asn1objectidentifier(name.substring(4));
        }
        else if (name.charat(0) >= '0' && name.charat(0) <= '9')
        {
            return new asn1objectidentifier(name);
        }

        asn1objectidentifier oid = (asn1objectidentifier)lookup.get(strings.tolowercase(name));
        if (oid == null)
        {
            throw new illegalargumentexception("unknown object id - " + name + " - passed to distinguished name");
        }

        return oid;
    }

    private string unescape(string elt)
    {
        if (elt.length() == 0 || (elt.indexof('\\') < 0 && elt.indexof('"') < 0))
        {
            return elt.trim();
        }

        char[] elts = elt.tochararray();
        boolean escaped = false;
        boolean quoted = false;
        stringbuffer buf = new stringbuffer(elt.length());
        int start = 0;

        // if it's an escaped hash string and not an actual encoding in string form
        // we need to leave it escaped.
        if (elts[0] == '\\')
        {
            if (elts[1] == '#')
            {
                start = 2;
                buf.append("\\#");
            }
        }

        boolean nonwhitespaceencountered = false;
        int     lastescaped = 0;

        for (int i = start; i != elts.length; i++)
        {
            char c = elts[i];

            if (c != ' ')
            {
                nonwhitespaceencountered = true;
            }

            if (c == '"')
            {
                if (!escaped)
                {
                    quoted = !quoted;
                }
                else
                {
                    buf.append(c);
                }
                escaped = false;
            }
            else if (c == '\\' && !(escaped || quoted))
            {
                escaped = true;
                lastescaped = buf.length();
            }
            else
            {
                if (c == ' ' && !escaped && !nonwhitespaceencountered)
                {
                    continue;
                }
                buf.append(c);
                escaped = false;
            }
        }

        if (buf.length() > 0)
        {
            while (buf.charat(buf.length() - 1) == ' ' && lastescaped != (buf.length() - 1))
            {
                buf.setlength(buf.length() - 1);
            }
        }

        return buf.tostring();
    }

    /**
     * takes an x509 dir name as a string of the format "c=au, st=victoria", or
     * some such, converting it into an ordered set of name attributes. lookup
     * should provide a table of lookups, indexed by lowercase only strings and
     * yielding a asn1objectidentifier, other than that oid. and numeric oids
     * will be processed automatically. the passed in converter is used to convert the
     * string values to the right of each equals sign to their asn.1 counterparts.
     * <br>
     * @param reverse true if we should start scanning from the end, false otherwise.
     * @param lookup table of names and oids.
     * @param dirname the string dirname
     * @param converter the converter to convert string values into their asn.1 equivalents
     */
    public x509name(
        boolean                 reverse,
        hashtable               lookup,
        string                  dirname,
        x509nameentryconverter  converter)
    {
        this.converter = converter;
        x509nametokenizer   ntok = new x509nametokenizer(dirname);

        while (ntok.hasmoretokens())
        {
            string  token = ntok.nexttoken();

            if (token.indexof('+') > 0)
            {
                x509nametokenizer   ptok = new x509nametokenizer(token, '+');

                addentry(lookup, ptok.nexttoken(), false);

                while (ptok.hasmoretokens())
                {
                    addentry(lookup, ptok.nexttoken(), true);
                }
            }
            else
            {
                addentry(lookup, token, false);
            }
        }

        if (reverse)
        {
            vector  o = new vector();
            vector  v = new vector();
            vector  a = new vector();

            int count = 1;

            for (int i = 0; i < this.ordering.size(); i++)
            {
                if (((boolean)this.added.elementat(i)).booleanvalue())
                {
                    o.insertelementat(this.ordering.elementat(i), count);
                    v.insertelementat(this.values.elementat(i), count);
                    a.insertelementat(this.added.elementat(i), count);
                    count++;
                }
                else
                {
                    o.insertelementat(this.ordering.elementat(i), 0);
                    v.insertelementat(this.values.elementat(i), 0);
                    a.insertelementat(this.added.elementat(i), 0);
                    count = 1;
                }
            }

            this.ordering = o;
            this.values = v;
            this.added = a;
        }
    }

    private void addentry(hashtable lookup, string token, boolean isadded)
    {
        x509nametokenizer vtok;
        string name;
        string value;asn1objectidentifier oid;
        vtok = new x509nametokenizer(token, '=');

        name = vtok.nexttoken();

        if (!vtok.hasmoretokens())
        {
           throw new illegalargumentexception("badly formatted directory string");
        }

        value = vtok.nexttoken();

        oid = decodeoid(name, lookup);

        this.ordering.addelement(oid);
        this.values.addelement(unescape(value));
        this.added.addelement(isadded);
    }

    /**
     * return a vector of the oids in the name, in the order they were found.
     */
    public vector getoids()
    {
        vector  v = new vector();

        for (int i = 0; i != ordering.size(); i++)
        {
            v.addelement(ordering.elementat(i));
        }

        return v;
    }

    /**
     * return a vector of the values found in the name, in the order they
     * were found.
     */
    public vector getvalues()
    {
        vector  v = new vector();

        for (int i = 0; i != values.size(); i++)
        {
            v.addelement(values.elementat(i));
        }

        return v;
    }

    /**
     * return a vector of the values found in the name, in the order they
     * were found, with the dn label corresponding to passed in oid.
     */
    public vector getvalues(
        asn1objectidentifier oid)
    {
        vector  v = new vector();

        for (int i = 0; i != values.size(); i++)
        {
            if (ordering.elementat(i).equals(oid))
            {
                string val = (string)values.elementat(i);

                if (val.length() > 2 && val.charat(0) == '\\' && val.charat(1) == '#')
                {
                    v.addelement(val.substring(1));
                }
                else
                {
                    v.addelement(val);
                }
            }
        }

        return v;
    }

    public asn1primitive toasn1primitive()
    {
        if (seq == null)
        {
            asn1encodablevector  vec = new asn1encodablevector();
            asn1encodablevector  svec = new asn1encodablevector();
            asn1objectidentifier  lstoid = null;
            
            for (int i = 0; i != ordering.size(); i++)
            {
                asn1encodablevector     v = new asn1encodablevector();
                asn1objectidentifier     oid = (asn1objectidentifier)ordering.elementat(i);

                v.add(oid);

                string  str = (string)values.elementat(i);

                v.add(converter.getconvertedvalue(oid, str));
 
                if (lstoid == null 
                    || ((boolean)this.added.elementat(i)).booleanvalue())
                {
                    svec.add(new dersequence(v));
                }
                else
                {
                    vec.add(new derset(svec));
                    svec = new asn1encodablevector();
                    
                    svec.add(new dersequence(v));
                }
                
                lstoid = oid;
            }
            
            vec.add(new derset(svec));
            
            seq = new dersequence(vec);
        }

        return seq;
    }

    /**
     * @param inorder if true the order of both x509 names must be the same,
     * as well as the values associated with each element.
     */
    public boolean equals(object obj, boolean inorder)
    {
        if (!inorder)
        {
            return this.equals(obj);
        }

        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof x509name || obj instanceof asn1sequence))
        {
            return false;
        }

        asn1primitive dero = ((asn1encodable)obj).toasn1primitive();

        if (this.toasn1primitive().equals(dero))
        {
            return true;
        }

        x509name other;

        try
        {
            other = x509name.getinstance(obj);
        }
        catch (illegalargumentexception e)
        {
            return false;
        }

        int      orderingsize = ordering.size();

        if (orderingsize != other.ordering.size())
        {
            return false;
        }

        for (int i = 0; i < orderingsize; i++)
        {
            asn1objectidentifier  oid = (asn1objectidentifier)ordering.elementat(i);
            asn1objectidentifier  ooid = (asn1objectidentifier)other.ordering.elementat(i);

            if (oid.equals(ooid))
            {
                string value = (string)values.elementat(i);
                string ovalue = (string)other.values.elementat(i);

                if (!equivalentstrings(value, ovalue))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    public int hashcode()
    {
        if (ishashcodecalculated)
        {
            return hashcodevalue;
        }

        ishashcodecalculated = true;

        // this needs to be order independent, like equals
        for (int i = 0; i != ordering.size(); i += 1)
        {
            string value = (string)values.elementat(i);

            value = canonicalize(value);
            value = stripinternalspaces(value);

            hashcodevalue ^= ordering.elementat(i).hashcode();
            hashcodevalue ^= value.hashcode();
        }

        return hashcodevalue;
    }

    /**
     * test for equality - note: case is ignored.
     */
    public boolean equals(object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof x509name || obj instanceof asn1sequence))
        {
            return false;
        }
        
        asn1primitive dero = ((asn1encodable)obj).toasn1primitive();
        
        if (this.toasn1primitive().equals(dero))
        {
            return true;
        }

        x509name other;

        try
        {
            other = x509name.getinstance(obj);
        }
        catch (illegalargumentexception e)
        { 
            return false;
        }

        int      orderingsize = ordering.size();

        if (orderingsize != other.ordering.size())
        {
            return false;
        }
        
        boolean[] indexes = new boolean[orderingsize];
        int       start, end, delta;

        if (ordering.elementat(0).equals(other.ordering.elementat(0)))   // guess forward
        {
            start = 0;
            end = orderingsize;
            delta = 1;
        }
        else  // guess reversed - most common problem
        {
            start = orderingsize - 1;
            end = -1;
            delta = -1;
        }

        for (int i = start; i != end; i += delta)
        {
            boolean              found = false;
            asn1objectidentifier  oid = (asn1objectidentifier)ordering.elementat(i);
            string               value = (string)values.elementat(i);

            for (int j = 0; j < orderingsize; j++)
            {
                if (indexes[j])
                {
                    continue;
                }

                asn1objectidentifier ooid = (asn1objectidentifier)other.ordering.elementat(j);

                if (oid.equals(ooid))
                {
                    string ovalue = (string)other.values.elementat(j);

                    if (equivalentstrings(value, ovalue))
                    {
                        indexes[j] = true;
                        found      = true;
                        break;
                    }
                }
            }

            if (!found)
            {
                return false;
            }
        }
        
        return true;
    }

    private boolean equivalentstrings(string s1, string s2)
    {
        string value = canonicalize(s1);
        string ovalue = canonicalize(s2);
        
        if (!value.equals(ovalue))
        {
            value = stripinternalspaces(value);
            ovalue = stripinternalspaces(ovalue);

            if (!value.equals(ovalue))
            {
                return false;
            }
        }

        return true;
    }

    private string canonicalize(string s)
    {
        string value = strings.tolowercase(s.trim());
        
        if (value.length() > 0 && value.charat(0) == '#')
        {
            asn1primitive obj = decodeobject(value);

            if (obj instanceof asn1string)
            {
                value = strings.tolowercase(((asn1string)obj).getstring().trim());
            }
        }

        return value;
    }

    private asn1primitive decodeobject(string ovalue)
    {
        try
        {
            return asn1primitive.frombytearray(hex.decode(ovalue.substring(1)));
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("unknown encoding in name: " + e);
        }
    }

    private string stripinternalspaces(
        string str)
    {
        stringbuffer res = new stringbuffer();

        if (str.length() != 0)
        {
            char    c1 = str.charat(0);

            res.append(c1);

            for (int k = 1; k < str.length(); k++)
            {
                char    c2 = str.charat(k);
                if (!(c1 == ' ' && c2 == ' '))
                {
                    res.append(c2);
                }
                c1 = c2;
            }
        }

        return res.tostring();
    }

    private void appendvalue(
        stringbuffer        buf,
        hashtable           oidsymbols,
        asn1objectidentifier oid,
        string              value)
    {
        string  sym = (string)oidsymbols.get(oid);

        if (sym != null)
        {
            buf.append(sym);
        }
        else
        {
            buf.append(oid.getid());
        }

        buf.append('=');

        int     index = buf.length();
        int     start = index;

        buf.append(value);

        int     end = buf.length();

        if (value.length() >= 2 && value.charat(0) == '\\' && value.charat(1) == '#')
        {
            index += 2;   
        }

        while (index != end)
        {
            if ((buf.charat(index) == ',')
               || (buf.charat(index) == '"')
               || (buf.charat(index) == '\\')
               || (buf.charat(index) == '+')
               || (buf.charat(index) == '=')
               || (buf.charat(index) == '<')
               || (buf.charat(index) == '>')
               || (buf.charat(index) == ';'))
            {
                buf.insert(index, "\\");
                index++;
                end++;
            }

            index++;
        }

        while (buf.charat(start) == ' ')
        {
            buf.insert(start, "\\");
            start += 2;
        }

        int endbuf = buf.length() - 1;

        while (endbuf >= 0 && buf.charat(endbuf) == ' ')
        {
            buf.insert(endbuf, '\\');
            endbuf--;
        }
    }

    /**
     * convert the structure to a string - if reverse is true the
     * oids and values are listed out starting with the last element
     * in the sequence (ala rfc 2253), otherwise the string will begin
     * with the first element of the structure. if no string definition
     * for the oid is found in oidsymbols the string value of the oid is
     * added. two standard symbol tables are provided defaultsymbols, and
     * rfc2253symbols as part of this class.
     *
     * @param reverse if true start at the end of the sequence and work back.
     * @param oidsymbols look up table strings for oids.
     */
    public string tostring(
        boolean     reverse,
        hashtable   oidsymbols)
    {
        stringbuffer            buf = new stringbuffer();
        vector                  components = new vector();
        boolean                 first = true;

        stringbuffer ava = null;

        for (int i = 0; i < ordering.size(); i++)
        {
            if (((boolean)added.elementat(i)).booleanvalue())
            {
                ava.append('+');
                appendvalue(ava, oidsymbols,
                    (asn1objectidentifier)ordering.elementat(i),
                    (string)values.elementat(i));
            }
            else
            {
                ava = new stringbuffer();
                appendvalue(ava, oidsymbols,
                    (asn1objectidentifier)ordering.elementat(i),
                    (string)values.elementat(i));
                components.addelement(ava);
            }
        }

        if (reverse)
        {
            for (int i = components.size() - 1; i >= 0; i--)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    buf.append(',');
                }

                buf.append(components.elementat(i).tostring());
            }
        }
        else
        {
            for (int i = 0; i < components.size(); i++)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    buf.append(',');
                }

                buf.append(components.elementat(i).tostring());
            }
        }

        return buf.tostring();
    }

    private string bytestostring(
        byte[] data)
    {
        char[]  cs = new char[data.length];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)(data[i] & 0xff);
        }

        return new string(cs);
    }
    
    public string tostring()
    {
        return tostring(defaultreverse, defaultsymbols);
    }
}
