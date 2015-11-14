package org.ripple.bouncycastle.asn1.x500.style;

import java.io.ioexception;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.derutf8string;
import org.ripple.bouncycastle.asn1.x500.attributetypeandvalue;
import org.ripple.bouncycastle.asn1.x500.rdn;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x500.x500namestyle;

public class rfc4519style
    implements x500namestyle
{
    public static final x500namestyle instance = new rfc4519style();

    public static final asn1objectidentifier businesscategory = new asn1objectidentifier("2.5.4.15");
    public static final asn1objectidentifier c = new asn1objectidentifier("2.5.4.6");
    public static final asn1objectidentifier cn = new asn1objectidentifier("2.5.4.3");
    public static final asn1objectidentifier dc = new asn1objectidentifier("0.9.2342.19200300.100.1.25");
    public static final asn1objectidentifier description = new asn1objectidentifier("2.5.4.13");
    public static final asn1objectidentifier destinationindicator = new asn1objectidentifier("2.5.4.27");
    public static final asn1objectidentifier distinguishedname = new asn1objectidentifier("2.5.4.49");
    public static final asn1objectidentifier dnqualifier = new asn1objectidentifier("2.5.4.46");
    public static final asn1objectidentifier enhancedsearchguide = new asn1objectidentifier("2.5.4.47");
    public static final asn1objectidentifier facsimiletelephonenumber = new asn1objectidentifier("2.5.4.23");
    public static final asn1objectidentifier generationqualifier = new asn1objectidentifier("2.5.4.44");
    public static final asn1objectidentifier givenname = new asn1objectidentifier("2.5.4.42");
    public static final asn1objectidentifier houseidentifier = new asn1objectidentifier("2.5.4.51");
    public static final asn1objectidentifier initials = new asn1objectidentifier("2.5.4.43");
    public static final asn1objectidentifier internationalisdnnumber = new asn1objectidentifier("2.5.4.25");
    public static final asn1objectidentifier l = new asn1objectidentifier("2.5.4.7");
    public static final asn1objectidentifier member = new asn1objectidentifier("2.5.4.31");
    public static final asn1objectidentifier name = new asn1objectidentifier("2.5.4.41");
    public static final asn1objectidentifier o = new asn1objectidentifier("2.5.4.10");
    public static final asn1objectidentifier ou = new asn1objectidentifier("2.5.4.11");
    public static final asn1objectidentifier owner = new asn1objectidentifier("2.5.4.32");
    public static final asn1objectidentifier physicaldeliveryofficename = new asn1objectidentifier("2.5.4.19");
    public static final asn1objectidentifier postaladdress = new asn1objectidentifier("2.5.4.16");
    public static final asn1objectidentifier postalcode = new asn1objectidentifier("2.5.4.17");
    public static final asn1objectidentifier postofficebox = new asn1objectidentifier("2.5.4.18");
    public static final asn1objectidentifier preferreddeliverymethod = new asn1objectidentifier("2.5.4.28");
    public static final asn1objectidentifier registeredaddress = new asn1objectidentifier("2.5.4.26");
    public static final asn1objectidentifier roleoccupant = new asn1objectidentifier("2.5.4.33");
    public static final asn1objectidentifier searchguide = new asn1objectidentifier("2.5.4.14");
    public static final asn1objectidentifier seealso = new asn1objectidentifier("2.5.4.34");
    public static final asn1objectidentifier serialnumber = new asn1objectidentifier("2.5.4.5");
    public static final asn1objectidentifier sn = new asn1objectidentifier("2.5.4.4");
    public static final asn1objectidentifier st = new asn1objectidentifier("2.5.4.8");
    public static final asn1objectidentifier street = new asn1objectidentifier("2.5.4.9");
    public static final asn1objectidentifier telephonenumber = new asn1objectidentifier("2.5.4.20");
    public static final asn1objectidentifier teletexterminalidentifier = new asn1objectidentifier("2.5.4.22");
    public static final asn1objectidentifier telexnumber = new asn1objectidentifier("2.5.4.21");
    public static final asn1objectidentifier title = new asn1objectidentifier("2.5.4.12");
    public static final asn1objectidentifier uid = new asn1objectidentifier("0.9.2342.19200300.100.1.1");
    public static final asn1objectidentifier uniquemember = new asn1objectidentifier("2.5.4.50");
    public static final asn1objectidentifier userpassword = new asn1objectidentifier("2.5.4.35");
    public static final asn1objectidentifier x121address = new asn1objectidentifier("2.5.4.24");
    public static final asn1objectidentifier x500uniqueidentifier = new asn1objectidentifier("2.5.4.45");

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
        defaultsymbols.put(businesscategory, "businesscategory");
        defaultsymbols.put(c, "c");
        defaultsymbols.put(cn, "cn");
        defaultsymbols.put(dc, "dc");
        defaultsymbols.put(description, "description");
        defaultsymbols.put(destinationindicator, "destinationindicator");
        defaultsymbols.put(distinguishedname, "distinguishedname");
        defaultsymbols.put(dnqualifier, "dnqualifier");
        defaultsymbols.put(enhancedsearchguide, "enhancedsearchguide");
        defaultsymbols.put(facsimiletelephonenumber, "facsimiletelephonenumber");
        defaultsymbols.put(generationqualifier, "generationqualifier");
        defaultsymbols.put(givenname, "givenname");
        defaultsymbols.put(houseidentifier, "houseidentifier");
        defaultsymbols.put(initials, "initials");
        defaultsymbols.put(internationalisdnnumber, "internationalisdnnumber");
        defaultsymbols.put(l, "l");
        defaultsymbols.put(member, "member");
        defaultsymbols.put(name, "name");
        defaultsymbols.put(o, "o");
        defaultsymbols.put(ou, "ou");
        defaultsymbols.put(owner, "owner");
        defaultsymbols.put(physicaldeliveryofficename, "physicaldeliveryofficename");
        defaultsymbols.put(postaladdress, "postaladdress");
        defaultsymbols.put(postalcode, "postalcode");
        defaultsymbols.put(postofficebox, "postofficebox");
        defaultsymbols.put(preferreddeliverymethod, "preferreddeliverymethod");
        defaultsymbols.put(registeredaddress, "registeredaddress");
        defaultsymbols.put(roleoccupant, "roleoccupant");
        defaultsymbols.put(searchguide, "searchguide");
        defaultsymbols.put(seealso, "seealso");
        defaultsymbols.put(serialnumber, "serialnumber");
        defaultsymbols.put(sn, "sn");
        defaultsymbols.put(st, "st");
        defaultsymbols.put(street, "street");
        defaultsymbols.put(telephonenumber, "telephonenumber");
        defaultsymbols.put(teletexterminalidentifier, "teletexterminalidentifier");
        defaultsymbols.put(telexnumber, "telexnumber");
        defaultsymbols.put(title, "title");
        defaultsymbols.put(uid, "uid");
        defaultsymbols.put(uniquemember, "uniquemember");
        defaultsymbols.put(userpassword, "userpassword");
        defaultsymbols.put(x121address, "x121address");
        defaultsymbols.put(x500uniqueidentifier, "x500uniqueidentifier");

        defaultlookup.put("businesscategory", businesscategory);
        defaultlookup.put("c", c);
        defaultlookup.put("cn", cn);
        defaultlookup.put("dc", dc);
        defaultlookup.put("description", description);
        defaultlookup.put("destinationindicator", destinationindicator);
        defaultlookup.put("distinguishedname", distinguishedname);
        defaultlookup.put("dnqualifier", dnqualifier);
        defaultlookup.put("enhancedsearchguide", enhancedsearchguide);
        defaultlookup.put("facsimiletelephonenumber", facsimiletelephonenumber);
        defaultlookup.put("generationqualifier", generationqualifier);
        defaultlookup.put("givenname", givenname);
        defaultlookup.put("houseidentifier", houseidentifier);
        defaultlookup.put("initials", initials);
        defaultlookup.put("internationalisdnnumber", internationalisdnnumber);
        defaultlookup.put("l", l);
        defaultlookup.put("member", member);
        defaultlookup.put("name", name);
        defaultlookup.put("o", o);
        defaultlookup.put("ou", ou);
        defaultlookup.put("owner", owner);
        defaultlookup.put("physicaldeliveryofficename", physicaldeliveryofficename);
        defaultlookup.put("postaladdress", postaladdress);
        defaultlookup.put("postalcode", postalcode);
        defaultlookup.put("postofficebox", postofficebox);
        defaultlookup.put("preferreddeliverymethod", preferreddeliverymethod);
        defaultlookup.put("registeredaddress", registeredaddress);
        defaultlookup.put("roleoccupant", roleoccupant);
        defaultlookup.put("searchguide", searchguide);
        defaultlookup.put("seealso", seealso);
        defaultlookup.put("serialnumber", serialnumber);
        defaultlookup.put("sn", sn);
        defaultlookup.put("st", st);
        defaultlookup.put("street", street);
        defaultlookup.put("telephonenumber", telephonenumber);
        defaultlookup.put("teletexterminalidentifier", teletexterminalidentifier);
        defaultlookup.put("telexnumber", telexnumber);
        defaultlookup.put("title", title);
        defaultlookup.put("uid", uid);
        defaultlookup.put("uniquemember", uniquemember);
        defaultlookup.put("userpassword", userpassword);
        defaultlookup.put("x121address", x121address);
        defaultlookup.put("x500uniqueidentifier", x500uniqueidentifier);

        // todo: need to add correct matching for equality comparisons.
    }

    protected rfc4519style()
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
            if (oid.equals(dc))
            {
                return new deria5string(value);
            }
            else if (oid.equals(c) || oid.equals(serialnumber) || oid.equals(dnqualifier)
                || oid.equals(telephonenumber))
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

    // parse backwards
    public rdn[] fromstring(string dirname)
    {
        rdn[] tmp = ietfutils.rdnsfromstring(dirname, this);
        rdn[] res = new rdn[tmp.length];

        for (int i = 0; i != tmp.length; i++)
        {
            res[res.length - i - 1] = tmp[i];
        }

        return res;
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

    // convert in reverse
    public string tostring(x500name name)
    {
        stringbuffer buf = new stringbuffer();
        boolean first = true;

        rdn[] rdns = name.getrdns();

        for (int i = rdns.length - 1; i >= 0; i--)
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
