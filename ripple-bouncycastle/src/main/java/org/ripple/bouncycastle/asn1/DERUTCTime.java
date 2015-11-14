package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.text.parseexception;
import java.text.simpledateformat;
import java.util.date;
import java.util.simpletimezone;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;

/**
 * utc time object.
 */
public class derutctime
    extends asn1primitive
{
    private byte[]      time;

    /**
     * return an utc time from the passed in object.
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static asn1utctime getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof asn1utctime)
        {
            return (asn1utctime)obj;
        }

        if (obj instanceof derutctime)
        {
            return new asn1utctime(((derutctime)obj).time);
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (asn1utctime)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an utc time from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static asn1utctime getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1object o = obj.getobject();

        if (explicit || o instanceof asn1utctime)
        {
            return getinstance(o);
        }
        else
        {
            return new asn1utctime(((asn1octetstring)o).getoctets());
        }
    }
    
    /**
     * the correct format for this is yymmddhhmmssz (it used to be that seconds were
     * never encoded. when you're creating one of these objects from scratch, that's
     * what you want to use, otherwise we'll try to deal with whatever gets read from
     * the input stream... (this is why the input format is different from the gettime()
     * method output).
     * <p>
     *
     * @param time the time string.
     */
    public derutctime(
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
     * base constructer from a java.util.date object
     */
    public derutctime(
        date time)
    {
        simpledateformat datef = new simpledateformat("yymmddhhmmss'z'");

        datef.settimezone(new simpletimezone(0,"z"));

        this.time = strings.tobytearray(datef.format(time));
    }

    derutctime(
        byte[]  time)
    {
        this.time = time;
    }

    /**
     * return the time as a date based on whatever a 2 digit year will return. for
     * standardised processing use getadjusteddate().
     *
     * @return the resulting date
     * @exception parseexception if the date string cannot be parsed.
     */
    public date getdate()
        throws parseexception
    {
        simpledateformat datef = new simpledateformat("yymmddhhmmssz");

        return datef.parse(gettime());
    }

    /**
     * return the time as an adjusted date
     * in the range of 1950 - 2049.
     *
     * @return a date in the range of 1950 to 2049.
     * @exception parseexception if the date string cannot be parsed.
     */
    public date getadjusteddate()
        throws parseexception
    {
        simpledateformat datef = new simpledateformat("yyyymmddhhmmssz");

        datef.settimezone(new simpletimezone(0, "z"));

        return datef.parse(getadjustedtime());
    }

    /**
     * return the time - always in the form of 
     *  yymmddhhmmssgmt(+hh:mm|-hh:mm).
     * <p>
     * normally in a certificate we would expect "z" rather than "gmt",
     * however adding the "gmt" means we can just use:
     * <pre>
     *     datef = new simpledateformat("yymmddhhmmssz");
     * </pre>
     * to read in the time and get a date which is compatible with our local
     * time zone.
     * <p>
     * <b>note:</b> in some cases, due to the local date processing, this
     * may lead to unexpected results. if you want to stick the normal
     * convention of 1950 to 2049 use the getadjustedtime() method.
     */
    public string gettime()
    {
        string stime = strings.frombytearray(time);

        //
        // standardise the format.
        //
        if (stime.indexof('-') < 0 && stime.indexof('+') < 0)
        {
            if (stime.length() == 11)
            {
                return stime.substring(0, 10) + "00gmt+00:00";
            }
            else
            {
                return stime.substring(0, 12) + "gmt+00:00";
            }
        }
        else
        {
            int index = stime.indexof('-');
            if (index < 0)
            {
                index = stime.indexof('+');
            }
            string d = stime;

            if (index == stime.length() - 3)
            {
                d += "00";
            }

            if (index == 10)
            {
                return d.substring(0, 10) + "00gmt" + d.substring(10, 13) + ":" + d.substring(13, 15);
            }
            else
            {
                return d.substring(0, 12) + "gmt" + d.substring(12, 15) + ":" +  d.substring(15, 17);
            }
        }
    }

    /**
     * return a time string as an adjusted date with a 4 digit year. this goes
     * in the range of 1950 - 2049.
     */
    public string getadjustedtime()
    {
        string   d = this.gettime();

        if (d.charat(0) < '5')
        {
            return "20" + d;
        }
        else
        {
            return "19" + d;
        }
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
        out.write(bertags.utc_time);

        int length = time.length;

        out.writelength(length);

        for (int i = 0; i != length; i++)
        {
            out.write((byte)time[i]);
        }
    }
    
    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof derutctime))
        {
            return false;
        }

        return arrays.areequal(time, ((derutctime)o).time);
    }
    
    public int hashcode()
    {
        return arrays.hashcode(time);
    }

    public string tostring() 
    {
      return strings.frombytearray(time);
    }
}
