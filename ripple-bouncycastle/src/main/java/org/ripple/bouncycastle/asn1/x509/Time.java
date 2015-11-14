package org.ripple.bouncycastle.asn1.x509;

import java.text.parseexception;
import java.text.simpledateformat;
import java.util.date;
import java.util.simpletimezone;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.derutctime;

public class time
    extends asn1object
    implements asn1choice
{
    asn1primitive time;

    public static time getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(obj.getobject()); // must be explicitly tagged
    }

    public time(
        asn1primitive   time)
    {
        if (!(time instanceof derutctime)
            && !(time instanceof dergeneralizedtime))
        {
            throw new illegalargumentexception("unknown object passed to time");
        }

        this.time = time; 
    }

    /**
     * creates a time object from a given date - if the date is between 1950
     * and 2049 a utctime object is generated, otherwise a generalizedtime
     * is used.
     */
    public time(
        date    date)
    {
        simpletimezone      tz = new simpletimezone(0, "z");
        simpledateformat    datef = new simpledateformat("yyyymmddhhmmss");

        datef.settimezone(tz);

        string  d = datef.format(date) + "z";
        int     year = integer.parseint(d.substring(0, 4));

        if (year < 1950 || year > 2049)
        {
            time = new dergeneralizedtime(d);
        }
        else
        {
            time = new derutctime(d.substring(2));
        }
    }

    public static time getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof time)
        {
            return (time)obj;
        }
        else if (obj instanceof derutctime)
        {
            return new time((derutctime)obj);
        }
        else if (obj instanceof dergeneralizedtime)
        {
            return new time((dergeneralizedtime)obj);
        }

        throw new illegalargumentexception("unknown object in factory: " + obj.getclass().getname());
    }

    public string gettime()
    {
        if (time instanceof derutctime)
        {
            return ((derutctime)time).getadjustedtime();
        }
        else
        {
            return ((dergeneralizedtime)time).gettime();
        }
    }

    public date getdate()
    {
        try
        {
            if (time instanceof derutctime)
            {
                return ((derutctime)time).getadjusteddate();
            }
            else
            {
                return ((dergeneralizedtime)time).getdate();
            }
        }
        catch (parseexception e)
        {         // this should never happen
            throw new illegalstateexception("invalid date string: " + e.getmessage());
        }
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * time ::= choice {
     *             utctime        utctime,
     *             generaltime    generalizedtime }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return time;
    }

    public string tostring()
    {
        return gettime();
    }
}
