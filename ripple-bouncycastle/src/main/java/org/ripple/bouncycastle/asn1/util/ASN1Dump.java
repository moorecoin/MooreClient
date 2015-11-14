package org.ripple.bouncycastle.asn1.util;

import java.io.ioexception;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.berapplicationspecific;
import org.ripple.bouncycastle.asn1.berconstructedoctetstring;
import org.ripple.bouncycastle.asn1.beroctetstring;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.berset;
import org.ripple.bouncycastle.asn1.bertaggedobject;
import org.ripple.bouncycastle.asn1.bertags;
import org.ripple.bouncycastle.asn1.derapplicationspecific;
import org.ripple.bouncycastle.asn1.derbmpstring;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.derboolean;
import org.ripple.bouncycastle.asn1.derenumerated;
import org.ripple.bouncycastle.asn1.derexternal;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dert61string;
import org.ripple.bouncycastle.asn1.derutctime;
import org.ripple.bouncycastle.asn1.derutf8string;
import org.ripple.bouncycastle.asn1.dervisiblestring;
import org.ripple.bouncycastle.util.encoders.hex;

public class asn1dump
{
    private static final string  tab = "    ";
    private static final int sample_size = 32;

    /**
     * dump a der object as a formatted string with indentation
     *
     * @param obj the asn1primitive to be dumped out.
     */
    static void _dumpasstring(
        string      indent,
        boolean     verbose,
        asn1primitive obj,
        stringbuffer    buf)
    {
        string nl = system.getproperty("line.separator");
        if (obj instanceof asn1sequence)
        {
            enumeration     e = ((asn1sequence)obj).getobjects();
            string          tab = indent + tab;

            buf.append(indent);
            if (obj instanceof bersequence)
            {
                buf.append("ber sequence");
            }
            else if (obj instanceof dersequence)
            {
                buf.append("der sequence");
            }
            else
            {
                buf.append("sequence");
            }

            buf.append(nl);

            while (e.hasmoreelements())
            {
                object  o = e.nextelement();

                if (o == null || o.equals(dernull.instance))
                {
                    buf.append(tab);
                    buf.append("null");
                    buf.append(nl);
                }
                else if (o instanceof asn1primitive)
                {
                    _dumpasstring(tab, verbose, (asn1primitive)o, buf);
                }
                else
                {
                    _dumpasstring(tab, verbose, ((asn1encodable)o).toasn1primitive(), buf);
                }
            }
        }
        else if (obj instanceof asn1taggedobject)
        {
            string          tab = indent + tab;

            buf.append(indent);
            if (obj instanceof bertaggedobject)
            {
                buf.append("ber tagged [");
            }
            else
            {
                buf.append("tagged [");
            }

            asn1taggedobject o = (asn1taggedobject)obj;

            buf.append(integer.tostring(o.gettagno()));
            buf.append(']');

            if (!o.isexplicit())
            {
                buf.append(" implicit ");
            }

            buf.append(nl);

            if (o.isempty())
            {
                buf.append(tab);
                buf.append("empty");
                buf.append(nl);
            }
            else
            {
                _dumpasstring(tab, verbose, o.getobject(), buf);
            }
        }
        else if (obj instanceof asn1set)
        {
            enumeration     e = ((asn1set)obj).getobjects();
            string          tab = indent + tab;

            buf.append(indent);

            if (obj instanceof berset)
            {
                buf.append("ber set");
            }
            else
            {
                buf.append("der set");
            }

            buf.append(nl);

            while (e.hasmoreelements())
            {
                object  o = e.nextelement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("null");
                    buf.append(nl);
                }
                else if (o instanceof asn1primitive)
                {
                    _dumpasstring(tab, verbose, (asn1primitive)o, buf);
                }
                else
                {
                    _dumpasstring(tab, verbose, ((asn1encodable)o).toasn1primitive(), buf);
                }
            }
        }
        else if (obj instanceof asn1octetstring)
        {
            asn1octetstring oct = (asn1octetstring)obj;

            if (obj instanceof beroctetstring || obj instanceof  berconstructedoctetstring)
            {
                buf.append(indent + "ber constructed octet string" + "[" + oct.getoctets().length + "] ");
            }
            else
            {
                buf.append(indent + "der octet string" + "[" + oct.getoctets().length + "] ");
            }
            if (verbose)
            {
                buf.append(dumpbinarydataasstring(indent, oct.getoctets()));
            }
            else
            {
                buf.append(nl);
            }
        }
        else if (obj instanceof asn1objectidentifier)
        {
            buf.append(indent + "objectidentifier(" + ((asn1objectidentifier)obj).getid() + ")" + nl);
        }
        else if (obj instanceof derboolean)
        {
            buf.append(indent + "boolean(" + ((derboolean)obj).istrue() + ")" + nl);
        }
        else if (obj instanceof asn1integer)
        {
            buf.append(indent + "integer(" + ((asn1integer)obj).getvalue() + ")" + nl);
        }
        else if (obj instanceof derbitstring)
        {
            derbitstring bt = (derbitstring)obj;
            buf.append(indent + "der bit string" + "[" + bt.getbytes().length + ", " + bt.getpadbits() + "] ");
            if (verbose)
            {
                buf.append(dumpbinarydataasstring(indent, bt.getbytes()));
            }
            else
            {
                buf.append(nl);
            }
        }
        else if (obj instanceof deria5string)
        {
            buf.append(indent + "ia5string(" + ((deria5string)obj).getstring() + ") " + nl);
        }
        else if (obj instanceof derutf8string)
        {
            buf.append(indent + "utf8string(" + ((derutf8string)obj).getstring() + ") " + nl);
        }
        else if (obj instanceof derprintablestring)
        {
            buf.append(indent + "printablestring(" + ((derprintablestring)obj).getstring() + ") " + nl);
        }
        else if (obj instanceof dervisiblestring)
        {
            buf.append(indent + "visiblestring(" + ((dervisiblestring)obj).getstring() + ") " + nl);
        }
        else if (obj instanceof derbmpstring)
        {
            buf.append(indent + "bmpstring(" + ((derbmpstring)obj).getstring() + ") " + nl);
        }
        else if (obj instanceof dert61string)
        {
            buf.append(indent + "t61string(" + ((dert61string)obj).getstring() + ") " + nl);
        }
        else if (obj instanceof derutctime)
        {
            buf.append(indent + "utctime(" + ((derutctime)obj).gettime() + ") " + nl);
        }
        else if (obj instanceof dergeneralizedtime)
        {
            buf.append(indent + "generalizedtime(" + ((dergeneralizedtime)obj).gettime() + ") " + nl);
        }
        else if (obj instanceof berapplicationspecific)
        {
            buf.append(outputapplicationspecific("ber", indent, verbose, obj, nl));
        }
        else if (obj instanceof derapplicationspecific)
        {
            buf.append(outputapplicationspecific("der", indent, verbose, obj, nl));
        }
        else if (obj instanceof derenumerated)
        {
            derenumerated en = (derenumerated) obj;
            buf.append(indent + "der enumerated(" + en.getvalue() + ")" + nl);
        }
        else if (obj instanceof derexternal)
        {
            derexternal ext = (derexternal) obj;
            buf.append(indent + "external " + nl);
            string          tab = indent + tab;
            if (ext.getdirectreference() != null)
            {
                buf.append(tab + "direct reference: " + ext.getdirectreference().getid() + nl);
            }
            if (ext.getindirectreference() != null)
            {
                buf.append(tab + "indirect reference: " + ext.getindirectreference().tostring() + nl);
            }
            if (ext.getdatavaluedescriptor() != null)
            {
                _dumpasstring(tab, verbose, ext.getdatavaluedescriptor(), buf);
            }
            buf.append(tab + "encoding: " + ext.getencoding() + nl);
            _dumpasstring(tab, verbose, ext.getexternalcontent(), buf);
        }
        else
        {
            buf.append(indent + obj.tostring() + nl);
        }
    }
    
    private static string outputapplicationspecific(string type, string indent, boolean verbose, asn1primitive obj, string nl)
    {
        derapplicationspecific app = (derapplicationspecific)obj;
        stringbuffer buf = new stringbuffer();

        if (app.isconstructed())
        {
            try
            {
                asn1sequence s = asn1sequence.getinstance(app.getobject(bertags.sequence));
                buf.append(indent + type + " applicationspecific[" + app.getapplicationtag() + "]" + nl);
                for (enumeration e = s.getobjects(); e.hasmoreelements();)
                {
                    _dumpasstring(indent + tab, verbose, (asn1primitive)e.nextelement(), buf);
                }
            }
            catch (ioexception e)
            {
                buf.append(e);
            }
            return buf.tostring();
        }

        return indent + type + " applicationspecific[" + app.getapplicationtag() + "] (" + new string(hex.encode(app.getcontents())) + ")" + nl;
    }

    /**
     * dump out a der object as a formatted string, in non-verbose mode.
     *
     * @param obj the asn1primitive to be dumped out.
     * @return  the resulting string.
     */
    public static string dumpasstring(
        object   obj)
    {
        return dumpasstring(obj, false);
    }

    /**
     * dump out the object as a string.
     *
     * @param obj  the object to be dumped
     * @param verbose  if true, dump out the contents of octet and bit strings.
     * @return  the resulting string.
     */
    public static string dumpasstring(
        object   obj,
        boolean  verbose)
    {
        stringbuffer buf = new stringbuffer();

        if (obj instanceof asn1primitive)
        {
            _dumpasstring("", verbose, (asn1primitive)obj, buf);
        }
        else if (obj instanceof asn1encodable)
        {
            _dumpasstring("", verbose, ((asn1encodable)obj).toasn1primitive(), buf);
        }
        else
        {
            return "unknown object type " + obj.tostring();
        }

        return buf.tostring();
    }

    private static string dumpbinarydataasstring(string indent, byte[] bytes)
    {
        string nl = system.getproperty("line.separator");
        stringbuffer buf = new stringbuffer();

        indent += tab;
        
        buf.append(nl);
        for (int i = 0; i < bytes.length; i += sample_size)
        {
            if (bytes.length - i > sample_size)
            {
                buf.append(indent);
                buf.append(new string(hex.encode(bytes, i, sample_size)));
                buf.append(tab);
                buf.append(calculateascstring(bytes, i, sample_size));
                buf.append(nl);
            }
            else
            {
                buf.append(indent);
                buf.append(new string(hex.encode(bytes, i, bytes.length - i)));
                for (int j = bytes.length - i; j != sample_size; j++)
                {
                    buf.append("  ");
                }
                buf.append(tab);
                buf.append(calculateascstring(bytes, i, bytes.length - i));
                buf.append(nl);
            }
        }
        
        return buf.tostring();
    }

    private static string calculateascstring(byte[] bytes, int off, int len)
    {
        stringbuffer buf = new stringbuffer();

        for (int i = off; i != off + len; i++)
        {
            if (bytes[i] >= ' ' && bytes[i] <= '~')
            {
                buf.append((char)bytes[i]);
            }
        }

        return buf.tostring();
    }
}
