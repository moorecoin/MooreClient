package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;
import java.util.stringtokenizer;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.util.ipaddress;

/**
 * the generalname object.
 * <pre>
 * generalname ::= choice {
 *      othername                       [0]     othername,
 *      rfc822name                      [1]     ia5string,
 *      dnsname                         [2]     ia5string,
 *      x400address                     [3]     oraddress,
 *      directoryname                   [4]     name,
 *      edipartyname                    [5]     edipartyname,
 *      uniformresourceidentifier       [6]     ia5string,
 *      ipaddress                       [7]     octet string,
 *      registeredid                    [8]     object identifier}
 *
 * othername ::= sequence {
 *      type-id    object identifier,
 *      value      [0] explicit any defined by type-id }
 *
 * edipartyname ::= sequence {
 *      nameassigner            [0]     directorystring optional,
 *      partyname               [1]     directorystring }
 * 
 * name ::= choice { rdnsequence }
 * </pre>
 */
public class generalname
    extends asn1object
    implements asn1choice
{
    public static final int othername                     = 0;
    public static final int rfc822name                    = 1;
    public static final int dnsname                       = 2;
    public static final int x400address                   = 3;
    public static final int directoryname                 = 4;
    public static final int edipartyname                  = 5;
    public static final int uniformresourceidentifier     = 6;
    public static final int ipaddress                     = 7;
    public static final int registeredid                  = 8;

    private asn1encodable obj;
    private int           tag;

    /**
     * @deprecated use x500name constructor.
     * @param dirname
     */
        public generalname(
        x509name  dirname)
    {
        this.obj = x500name.getinstance(dirname);
        this.tag = 4;
    }

    public generalname(
        x500name  dirname)
    {
        this.obj = dirname;
        this.tag = 4;
    }

    /**
     * when the subjectaltname extension contains an internet mail address,
     * the address must be included as an rfc822name. the format of an
     * rfc822name is an "addr-spec" as defined in rfc 822 [rfc 822].
     *
     * when the subjectaltname extension contains a domain name service
     * label, the domain name must be stored in the dnsname (an ia5string).
     * the name must be in the "preferred name syntax," as specified by rfc
     * 1034 [rfc 1034].
     *
     * when the subjectaltname extension contains a uri, the name must be
     * stored in the uniformresourceidentifier (an ia5string). the name must
     * be a non-relative url, and must follow the url syntax and encoding
     * rules specified in [rfc 1738].  the name must include both a scheme
     * (e.g., "http" or "ftp") and a scheme-specific-part.  the scheme-
     * specific-part must include a fully qualified domain name or ip
     * address as the host.
     *
     * when the subjectaltname extension contains a ipaddress, the address
     * must be stored in the octet string in "network byte order," as
     * specified in rfc 791 [rfc 791]. the least significant bit (lsb) of
     * each octet is the lsb of the corresponding byte in the network
     * address. for ip version 4, as specified in rfc 791, the octet string
     * must contain exactly four octets.  for ip version 6, as specified in
     * rfc 1883, the octet string must contain exactly sixteen octets [rfc
     * 1883].
     */
    public generalname(
        int           tag,
        asn1encodable name)
    {
        this.obj = name;
        this.tag = tag;
    }
    
    /**
     * create a generalname for the given tag from the passed in string.
     * <p>
     * this constructor can handle:
     * <ul>
     * <li>rfc822name
     * <li>ipaddress
     * <li>directoryname
     * <li>dnsname
     * <li>uniformresourceidentifier
     * <li>registeredid
     * </ul>
     * for x400address, othername and edipartyname there is no common string
     * format defined.
     * <p>
     * note: a directory name can be encoded in different ways into a byte
     * representation. be aware of this if the byte representation is used for
     * comparing results.
     *
     * @param tag tag number
     * @param name string representation of name
     * @throws illegalargumentexception if the string encoding is not correct or     *             not supported.
     */
    public generalname(
        int       tag,
        string    name)
    {
        this.tag = tag;

        if (tag == rfc822name || tag == dnsname || tag == uniformresourceidentifier)
        {
            this.obj = new deria5string(name);
        }
        else if (tag == registeredid)
        {
            this.obj = new asn1objectidentifier(name);
        }
        else if (tag == directoryname)
        {
            this.obj = new x500name(name);
        }
        else if (tag == ipaddress)
        {
            byte[] enc = togeneralnameencoding(name);
            if (enc != null)
            {
                this.obj = new deroctetstring(enc);
            }
            else
            {
                throw new illegalargumentexception("ip address is invalid");
            }
        }
        else
        {
            throw new illegalargumentexception("can't process string for tag: " + tag);
        }
    }
    
    public static generalname getinstance(
        object obj)
    {
        if (obj == null || obj instanceof generalname)
        {
            return (generalname)obj;
        }

        if (obj instanceof asn1taggedobject)
        {
            asn1taggedobject    tagobj = (asn1taggedobject)obj;
            int                 tag = tagobj.gettagno();

            switch (tag)
            {
            case othername:
                return new generalname(tag, asn1sequence.getinstance(tagobj, false));
            case rfc822name:
                return new generalname(tag, deria5string.getinstance(tagobj, false));
            case dnsname:
                return new generalname(tag, deria5string.getinstance(tagobj, false));
            case x400address:
                throw new illegalargumentexception("unknown tag: " + tag);
            case directoryname:
                return new generalname(tag, x500name.getinstance(tagobj, true));
            case edipartyname:
                return new generalname(tag, asn1sequence.getinstance(tagobj, false));
            case uniformresourceidentifier:
                return new generalname(tag, deria5string.getinstance(tagobj, false));
            case ipaddress:
                return new generalname(tag, asn1octetstring.getinstance(tagobj, false));
            case registeredid:
                return new generalname(tag, asn1objectidentifier.getinstance(tagobj, false));
            }
        }

        if (obj instanceof byte[])
        {
            try
            {
                return getinstance(asn1primitive.frombytearray((byte[])obj));
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("unable to parse encoded general name");
            }
        }

        throw new illegalargumentexception("unknown object in getinstance: " + obj.getclass().getname());
    }

    public static generalname getinstance(
        asn1taggedobject tagobj,
        boolean          explicit)
    {
        return generalname.getinstance(asn1taggedobject.getinstance(tagobj, true));
    }

    public int gettagno()
    {
        return tag;
    }

    public asn1encodable getname()
    {
        return obj;
    }

    public string tostring()
    {
        stringbuffer buf = new stringbuffer();

        buf.append(tag);
        buf.append(": ");
        switch (tag)
        {
        case rfc822name:
        case dnsname:
        case uniformresourceidentifier:
            buf.append(deria5string.getinstance(obj).getstring());
            break;
        case directoryname:
            buf.append(x500name.getinstance(obj).tostring());
            break;
        default:
            buf.append(obj.tostring());
        }
        return buf.tostring();
    }

    private byte[] togeneralnameencoding(string ip)
    {
        if (ipaddress.isvalidipv6withnetmask(ip) || ipaddress.isvalidipv6(ip))
        {
            int    slashindex = ip.indexof('/');

            if (slashindex < 0)
            {
                byte[] addr = new byte[16];
                int[]  parsedip = parseipv6(ip);
                copyints(parsedip, addr, 0);

                return addr;
            }
            else
            {
                byte[] addr = new byte[32];
                int[]  parsedip = parseipv6(ip.substring(0, slashindex));
                copyints(parsedip, addr, 0);
                string mask = ip.substring(slashindex + 1);
                if (mask.indexof(':') > 0)
                {
                    parsedip = parseipv6(mask);
                }
                else
                {
                    parsedip = parsemask(mask);
                }
                copyints(parsedip, addr, 16);

                return addr;
            }
        }
        else if (ipaddress.isvalidipv4withnetmask(ip) || ipaddress.isvalidipv4(ip))
        {
            int    slashindex = ip.indexof('/');

            if (slashindex < 0)
            {
                byte[] addr = new byte[4];

                parseipv4(ip, addr, 0);

                return addr;
            }
            else
            {
                byte[] addr = new byte[8];

                parseipv4(ip.substring(0, slashindex), addr, 0);

                string mask = ip.substring(slashindex + 1);
                if (mask.indexof('.') > 0)
                {
                    parseipv4(mask, addr, 4);
                }
                else
                {
                    parseipv4mask(mask, addr, 4);
                }

                return addr;
            }
        }

        return null;
    }

    private void parseipv4mask(string mask, byte[] addr, int offset)
    {
        int   maskval = integer.parseint(mask);

        for (int i = 0; i != maskval; i++)
        {
            addr[(i / 8) + offset] |= 1 << (7 - (i % 8));
        }
    }

    private void parseipv4(string ip, byte[] addr, int offset)
    {
        stringtokenizer stok = new stringtokenizer(ip, "./");
        int    index = 0;

        while (stok.hasmoretokens())
        {
            addr[offset + index++] = (byte)integer.parseint(stok.nexttoken());
        }
    }

    private int[] parsemask(string mask)
    {
        int[] res = new int[8];
        int   maskval = integer.parseint(mask);

        for (int i = 0; i != maskval; i++)
        {
            res[i / 16] |= 1 << (15 - (i % 16));
        }
        return res;
    }

    private void copyints(int[] parsedip, byte[] addr, int offset)
    {
        for (int i = 0; i != parsedip.length; i++)
        {
            addr[(i * 2) + offset] = (byte)(parsedip[i] >> 8);
            addr[(i * 2 + 1) + offset] = (byte)parsedip[i];
        }
    }

    private int[] parseipv6(string ip)
    {
        stringtokenizer stok = new stringtokenizer(ip, ":", true);
        int index = 0;
        int[] val = new int[8];

        if (ip.charat(0) == ':' && ip.charat(1) == ':')
        {
           stok.nexttoken(); // skip the first one
        }

        int doublecolon = -1;

        while (stok.hasmoretokens())
        {
            string e = stok.nexttoken();

            if (e.equals(":"))
            {
                doublecolon = index;
                val[index++] = 0;
            }
            else
            {
                if (e.indexof('.') < 0)
                {
                    val[index++] = integer.parseint(e, 16);
                    if (stok.hasmoretokens())
                    {
                        stok.nexttoken();
                    }
                }
                else
                {
                    stringtokenizer etok = new stringtokenizer(e, ".");

                    val[index++] = (integer.parseint(etok.nexttoken()) << 8) | integer.parseint(etok.nexttoken());
                    val[index++] = (integer.parseint(etok.nexttoken()) << 8) | integer.parseint(etok.nexttoken());
                }
            }
        }

        if (index != val.length)
        {
            system.arraycopy(val, doublecolon, val, val.length - (index - doublecolon), index - doublecolon);
            for (int i = doublecolon; i != val.length - (index - doublecolon); i++)
            {
                val[i] = 0;
            }
        }

        return val;
    }

    public asn1primitive toasn1primitive()
    {
        if (tag == directoryname)       // directoryname is explicitly tagged as it is a choice
        {
            return new dertaggedobject(true, tag, obj);
        }
        else
        {
            return new dertaggedobject(false, tag, obj);
        }
    }
}
