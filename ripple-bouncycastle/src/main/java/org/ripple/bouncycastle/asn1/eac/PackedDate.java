package org.ripple.bouncycastle.asn1.eac;

import java.text.parseexception;
import java.text.simpledateformat;
import java.util.date;
import java.util.simpletimezone;

import org.ripple.bouncycastle.util.arrays;

/**
 * eac encoding date object
 */
public class packeddate
{
    private byte[]      time;

    public packeddate(
        string time)
    {
        this.time = convert(time);
    }

    /**
     * base constructer from a java.util.date object
     */
    public packeddate(
        date time)
    {
        simpledateformat datef = new simpledateformat("yymmdd'z'");

        datef.settimezone(new simpletimezone(0,"z"));

        this.time = convert(datef.format(time));
    }

    private byte[] convert(string stime)
    {
        char[] digs = stime.tochararray();
        byte[] date = new byte[6];

        for (int i = 0; i != 6; i++)
        {
            date[i] = (byte)(digs[i] - '0');
        }

        return date;
    }

    packeddate(
        byte[] bytes)
    {
        this.time = bytes;
    }

    /**
     * return the time as a date based on whatever a 2 digit year will return. for
     * standardised processing use getadjusteddate().
     *
     * @return the resulting date
     * @exception java.text.parseexception if the date string cannot be parsed.
     */
    public date getdate()
        throws parseexception
    {
        simpledateformat datef = new simpledateformat("yyyymmdd");

        return datef.parse("20" + tostring());
    }

    public int hashcode()
    {
        return arrays.hashcode(time);
    }

    public boolean equals(object o)
    {
        if (!(o instanceof packeddate))
        {
            return false;
        }

        packeddate other = (packeddate)o;

        return arrays.areequal(time, other.time);
    }

    public string tostring() 
    {
        char[]  datec = new char[time.length];

        for (int i = 0; i != datec.length; i++)
        {
            datec[i] = (char)((time[i] & 0xff) + '0');
        }

        return new string(datec);
    }

    public byte[] getencoding()
    {
        return time;
    }
}
