package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.text.parseexception;
import java.text.simpledateformat;
import java.util.date;
import java.util.simpletimezone;
import java.util.timezone;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * generalized time object.
 */
public class dergeneralizedtime
    extends asn1primitive
{
    private byte[]      time;

    /**
     * return a generalized time from the passed in object
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static asn1generalizedtime getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof asn1generalizedtime)
        {
            return (asn1generalizedtime)obj;
        }

        if (obj instanceof dergeneralizedtime)
        {
            return new asn1generalizedtime(((dergeneralizedtime)obj).time);
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (asn1generalizedtime)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return a generalized time object from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static asn1generalizedtime getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof dergeneralizedtime)
        {
            return getinstance(o);
        }
        else
        {
            return new asn1generalizedtime(((asn1octetstring)o).getoctets());
        }
    }
    
    /**
     * the correct format for this is yyyymmddhhmmss[.f]z, or without the z
     * for local time, or z+-hhmm on the end, for difference between local
     * time and utc time. the fractional second amount f must consist of at
     * least one number with trailing zeroes removed.
     *
     * @param time the time string.
     * @exception illegalargumentexception if string is an illegal format.
     */
    public dergeneralizedtime(
        string  time)
    {
        this.time = strings.tobytearray(time);
        try
        {
            this.getdate();
        }
        catch (parseexception e)
        {
            throw new illegalargumentexception("invalid date string: " + e.getmessage());
        }
    }

    /**
     * base constructor from a java.util.date object
     */
    public dergeneralizedtime(
        date time)
    {
        simpledateformat datef = new simpledateformat("yyyymmddhhmmss'z'");

        datef.settimezone(new simpletimezone(0,"z"));

        this.time = strings.tobytearray(datef.format(time));
    }

    dergeneralizedtime(
        byte[]  bytes)
    {
        this.time = bytes;
    }

    /**
     * return the time.
     * @return the time string as it appeared in the encoded object.
     */
    public string gettimestring()
    {
        return strings.frombytearray(time);
    }
    
    /**
     * return the time - always in the form of 
     *  yyyymmddhhmmssgmt(+hh:mm|-hh:mm).
     * <p>
     * normally in a certificate we would expect "z" rather than "gmt",
     * however adding the "gmt" means we can just use:
     * <pre>
     *     datef = new simpledateformat("yyyymmddhhmmssz");
     * </pre>
     * to read in the time and get a date which is compatible with our local
     * time zone.
     */
    public string gettime()
    {
        string stime = strings.frombytearray(time);

        //
        // standardise the format.
        //             
        if (stime.charat(stime.length() - 1) == 'z')
        {
            return stime.substring(0, stime.length() - 1) + "gmt+00:00";
        }
        else
        {
            int signpos = stime.length() - 5;
            char sign = stime.charat(signpos);
            if (sign == '-' || sign == '+')
            {
                return stime.substring(0, signpos)
                    + "gmt"
                    + stime.substring(signpos, signpos + 3)
                    + ":"
                    + stime.substring(signpos + 3);
            }
            else
            {
                signpos = stime.length() - 3;
                sign = stime.charat(signpos);
                if (sign == '-' || sign == '+')
                {
                    return stime.substring(0, signpos)
                        + "gmt"
                        + stime.substring(signpos)
                        + ":00";
                }
            }
        }            
        return stime + calculategmtoffset();
    }

    private string calculategmtoffset()
    {
        string sign = "+";
        timezone timezone = timezone.getdefault();
        int offset = timezone.getrawoffset();
        if (offset < 0)
        {
            sign = "-";
            offset = -offset;
        }
        int hours = offset / (60 * 60 * 1000);
        int minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);

        try
        {
            if (timezone.usedaylighttime() && timezone.indaylighttime(this.getdate()))
            {
                hours += sign.equals("+") ? 1 : -1;
            }
        }
        catch (parseexception e)
        {
            // we'll do our best and ignore daylight savings
        }

        return "gmt" + sign + convert(hours) + ":" + convert(minutes);
    }

    private string convert(int time)
    {
        if (time < 10)
        {
            return "0" + time;
        }

        return integer.tostring(time);
    }

    public date getdate()
        throws parseexception
    {
        simpledateformat datef;
        string stime = strings.frombytearray(time);
        string d = stime;

        if (stime.endswith("z"))
        {
            if (hasfractionalseconds())
            {
                datef = new simpledateformat("yyyymmddhhmmss.sss'z'");
            }
            else
            {
                datef = new simpledateformat("yyyymmddhhmmss'z'");
            }

            datef.settimezone(new simpletimezone(0, "z"));
        }
        else if (stime.indexof('-') > 0 || stime.indexof('+') > 0)
        {
            d = this.gettime();
            if (hasfractionalseconds())
            { 
                datef = new simpledateformat("yyyymmddhhmmss.sssz");
            }
            else
            {
                datef = new simpledateformat("yyyymmddhhmmssz");
            }

            datef.settimezone(new simpletimezone(0, "z"));
        }
        else
        {
            if (hasfractionalseconds())
            {
                datef = new simpledateformat("yyyymmddhhmmss.sss");
            }
            else
            {
                datef = new simpledateformat("yyyymmddhhmmss");
            }

            datef.settimezone(new simpletimezone(0, timezone.getdefault().getid()));
        }

        if (hasfractionalseconds())
        {
            // java misinterprets extra digits as being milliseconds...
            string frac = d.substring(14);
            int    index;
            for (index = 1; index < frac.length(); index++)
            {
                char ch = frac.charat(index);
                if (!('0' <= ch && ch <= '9'))
                {
                    break;        
                }
            }

            if (index - 1 > 3)
            {
                frac = frac.substring(0, 4) + frac.substring(index);
                d = d.substring(0, 14) + frac;
            }
            else if (index - 1 == 1)
            {
                frac = frac.substring(0, index) + "00" + frac.substring(index);
                d = d.substring(0, 14) + frac;
            }
            else if (index - 1 == 2)
            {
                frac = frac.substring(0, index) + "0" + frac.substring(index);
                d = d.substring(0, 14) + frac;
            }
        }

        return datef.parse(d);
    }

    private boolean hasfractionalseconds()
    {
        for (int i = 0; i != time.length; i++)
        {
            if (time[i] == '.')
            {
                if (i == 14)
                {
                    return true;
                }
            }
        }
        return false;
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
    {
        int length = time.length;

        return 1 + streamutil.calculatebodylength(length) + length;
    }

    void encode(
        asn1outputstream  out)
        throws ioexception
    {
        out.writeencoded(bertags.generalized_time, time);
    }
    
    boolean asn1equals(
        asn1primitive  o)
    {
        if (!(o instanceof dergeneralizedtime))
        {
            return false;
        }

        return arrays.areequal(time, ((dergeneralizedtime)o).time);
    }
    
    public int hashcode()
    {
        return arrays.hashcode(time);
    }
}
