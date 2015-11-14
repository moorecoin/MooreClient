package org.ripple.bouncycastle.asn1.x500.style;

import java.io.ioexception;
import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.deruniversalstring;
import org.ripple.bouncycastle.asn1.x500.attributetypeandvalue;
import org.ripple.bouncycastle.asn1.x500.rdn;
import org.ripple.bouncycastle.asn1.x500.x500namebuilder;
import org.ripple.bouncycastle.asn1.x500.x500namestyle;
import org.ripple.bouncycastle.util.strings;
import org.ripple.bouncycastle.util.encoders.hex;

public class ietfutils
{
    private static string unescape(string elt)
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
        char    hex1 = 0;

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
                if (escaped && ishexdigit(c))
                {
                    if (hex1 != 0)
                    {
                        buf.append((char)(converthex(hex1) * 16 + converthex(c)));
                        escaped = false;
                        hex1 = 0;
                        continue;
                    }
                    hex1 = c;
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

    private static boolean ishexdigit(char c)
    {
        return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('a' <= c && c <= 'f');
    }

    private static int converthex(char c)
    {
        if ('0' <= c && c <= '9')
        {
            return c - '0';
        }
        if ('a' <= c && c <= 'f')
        {
            return c - 'a' + 10;
        }
        return c - 'a' + 10;
    }

    public static rdn[] rdnsfromstring(string name, x500namestyle x500style)
    {
        x500nametokenizer ntok = new x500nametokenizer(name);
        x500namebuilder builder = new x500namebuilder(x500style);

        while (ntok.hasmoretokens())
        {
            string  token = ntok.nexttoken();

            if (token.indexof('+') > 0)
            {
                x500nametokenizer   ptok = new x500nametokenizer(token, '+');
                x500nametokenizer   vtok = new x500nametokenizer(ptok.nexttoken(), '=');

                string              attr = vtok.nexttoken();

                if (!vtok.hasmoretokens())
                {
                    throw new illegalargumentexception("badly formatted directory string");
                }

                string               value = vtok.nexttoken();
                asn1objectidentifier oid = x500style.attrnametooid(attr.trim());

                if (ptok.hasmoretokens())
                {
                    vector oids = new vector();
                    vector values = new vector();

                    oids.addelement(oid);
                    values.addelement(unescape(value));

                    while (ptok.hasmoretokens())
                    {
                        vtok = new x500nametokenizer(ptok.nexttoken(), '=');

                        attr = vtok.nexttoken();

                        if (!vtok.hasmoretokens())
                        {
                            throw new illegalargumentexception("badly formatted directory string");
                        }

                        value = vtok.nexttoken();
                        oid = x500style.attrnametooid(attr.trim());


                        oids.addelement(oid);
                        values.addelement(unescape(value));
                    }

                    builder.addmultivaluedrdn(tooidarray(oids), tovaluearray(values));
                }
                else
                {
                    builder.addrdn(oid, unescape(value));
                }
            }
            else
            {
                x500nametokenizer   vtok = new x500nametokenizer(token, '=');

                string              attr = vtok.nexttoken();

                if (!vtok.hasmoretokens())
                {
                    throw new illegalargumentexception("badly formatted directory string");
                }

                string               value = vtok.nexttoken();
                asn1objectidentifier oid = x500style.attrnametooid(attr.trim());

                builder.addrdn(oid, unescape(value));
            }
        }

        return builder.build().getrdns();
    }

    private static string[] tovaluearray(vector values)
    {
        string[] tmp = new string[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = (string)values.elementat(i);
        }

        return tmp;
    }

    private static asn1objectidentifier[] tooidarray(vector oids)
    {
        asn1objectidentifier[] tmp = new asn1objectidentifier[oids.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = (asn1objectidentifier)oids.elementat(i);
        }

        return tmp;
    }

    public static string[] findattrnamesforoid(
        asn1objectidentifier oid,
        hashtable            lookup)
    {
        int count = 0;
        for (enumeration en = lookup.elements(); en.hasmoreelements();)
        {
            if (oid.equals(en.nextelement()))
            {
                count++;
            }
        }

        string[] aliases = new string[count];
        count = 0;

        for (enumeration en = lookup.keys(); en.hasmoreelements();)
        {
            string key = (string)en.nextelement();
            if (oid.equals(lookup.get(key)))
            {
                aliases[count++] = key;
            }
        }

        return aliases;
    }

    public static asn1objectidentifier decodeattrname(
        string      name,
        hashtable   lookup)
    {
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

    public static asn1encodable valuefromhexstring(
        string  str,
        int     off)
        throws ioexception
    {
        byte[] data = new byte[(str.length() - off) / 2];
        for (int index = 0; index != data.length; index++)
        {
            char left = str.charat((index * 2) + off);
            char right = str.charat((index * 2) + off + 1);

            data[index] = (byte)((converthex(left) << 4) | converthex(right));
        }

        return asn1primitive.frombytearray(data);
    }

    public static void appendrdn(
        stringbuffer          buf,
        rdn                   rdn,
        hashtable             oidsymbols)
    {
        if (rdn.ismultivalued())
        {
            attributetypeandvalue[] atv = rdn.gettypesandvalues();
            boolean firstatv = true;

            for (int j = 0; j != atv.length; j++)
            {
                if (firstatv)
                {
                    firstatv = false;
                }
                else
                {
                    buf.append('+');
                }

                ietfutils.appendtypeandvalue(buf, atv[j], oidsymbols);
            }
        }
        else
        {
            ietfutils.appendtypeandvalue(buf, rdn.getfirst(), oidsymbols);
        }
    }

    public static void appendtypeandvalue(
        stringbuffer          buf,
        attributetypeandvalue typeandvalue,
        hashtable             oidsymbols)
    {
        string  sym = (string)oidsymbols.get(typeandvalue.gettype());

        if (sym != null)
        {
            buf.append(sym);
        }
        else
        {
            buf.append(typeandvalue.gettype().getid());
        }

        buf.append('=');

        buf.append(valuetostring(typeandvalue.getvalue()));
    }

    public static string valuetostring(asn1encodable value)
    {
        stringbuffer vbuf = new stringbuffer();

        if (value instanceof asn1string && !(value instanceof deruniversalstring))
        {
            string v = ((asn1string)value).getstring();
            if (v.length() > 0 && v.charat(0) == '#')
            {
                vbuf.append("\\" + v);
            }
            else
            {
                vbuf.append(v);
            }
        }
        else
        {
            try
            {
                vbuf.append("#" + bytestostring(hex.encode(value.toasn1primitive().getencoded(asn1encoding.der))));
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("other value has no encoded form");
            }
        }

        int     end = vbuf.length();
        int     index = 0;

        if (vbuf.length() >= 2 && vbuf.charat(0) == '\\' && vbuf.charat(1) == '#')
        {
            index += 2;
        }

        while (index != end)
        {
            if ((vbuf.charat(index) == ',')
               || (vbuf.charat(index) == '"')
               || (vbuf.charat(index) == '\\')
               || (vbuf.charat(index) == '+')
               || (vbuf.charat(index) == '=')
               || (vbuf.charat(index) == '<')
               || (vbuf.charat(index) == '>')
               || (vbuf.charat(index) == ';'))
            {
                vbuf.insert(index, "\\");
                index++;
                end++;
            }

            index++;
        }

        int start = 0;
        if (vbuf.length() > 0)
        {
            while (vbuf.charat(start) == ' ')
            {
                vbuf.insert(start, "\\");
                start += 2;
            }
        }

        int endbuf = vbuf.length() - 1;

        while (endbuf >= 0 && vbuf.charat(endbuf) == ' ')
        {
            vbuf.insert(endbuf, '\\');
            endbuf--;
        }

        return vbuf.tostring();
    }

    private static string bytestostring(
        byte[] data)
    {
        char[]  cs = new char[data.length];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)(data[i] & 0xff);
        }

        return new string(cs);
    }

    public static string canonicalize(string s)
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

        value = stripinternalspaces(value);

        return value;
    }

    private static asn1primitive decodeobject(string ovalue)
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

    public static string stripinternalspaces(
        string str)
    {
        stringbuffer res = new stringbuffer();

        if (str.length() != 0)
        {
            char c1 = str.charat(0);

            res.append(c1);

            for (int k = 1; k < str.length(); k++)
            {
                char c2 = str.charat(k);
                if (!(c1 == ' ' && c2 == ' '))
                {
                    res.append(c2);
                }
                c1 = c2;
            }
        }

        return res.tostring();
    }

    public static boolean rdnareequal(rdn rdn1, rdn rdn2)
    {
        if (rdn1.ismultivalued())
        {
            if (rdn2.ismultivalued())
            {
                attributetypeandvalue[] atvs1 = rdn1.gettypesandvalues();
                attributetypeandvalue[] atvs2 = rdn2.gettypesandvalues();

                if (atvs1.length != atvs2.length)
                {
                    return false;
                }

                for (int i = 0; i != atvs1.length; i++)
                {
                    if (!atvareequal(atvs1[i], atvs2[i]))
                    {
                        return false;
                    }
                }
            }
            else
            {
                return false;
            }
        }
        else
        {
            if (!rdn2.ismultivalued())
            {
                return atvareequal(rdn1.getfirst(), rdn2.getfirst());
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    private static boolean atvareequal(attributetypeandvalue atv1, attributetypeandvalue atv2)
    {
        if (atv1 == atv2)
        {
            return true;
        }

        if (atv1 == null)
        {
            return false;
        }

        if (atv2 == null)
        {
            return false;
        }

        asn1objectidentifier o1 = atv1.gettype();
        asn1objectidentifier o2 = atv2.gettype();

        if (!o1.equals(o2))
        {
            return false;
        }

        string v1 = ietfutils.canonicalize(ietfutils.valuetostring(atv1.getvalue()));
        string v2 = ietfutils.canonicalize(ietfutils.valuetostring(atv2.getvalue()));

        if (!v1.equals(v2))
        {
            return false;
        }

        return true;
    }
}
