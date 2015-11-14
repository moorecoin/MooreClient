package org.ripple.bouncycastle.util;

public class ipaddress
{
    /**
     * validate the given ipv4 or ipv6 address.
     *
     * @param address the ip address as a string.
     *
     * @return true if a valid address, false otherwise
     */
    public static boolean isvalid(
        string address)
    {
        return isvalidipv4(address) || isvalidipv6(address);
    }

    /**
     * validate the given ipv4 or ipv6 address and netmask.
     *
     * @param address the ip address as a string.
     *
     * @return true if a valid address with netmask, false otherwise
     */
    public static boolean isvalidwithnetmask(
        string address)
    {
        return isvalidipv4withnetmask(address) || isvalidipv6withnetmask(address);
    }

    /**
     * validate the given ipv4 address.
     * 
     * @param address the ip address as a string.
     *
     * @return true if a valid ipv4 address, false otherwise
     */
    public static boolean isvalidipv4(
        string address)
    {
        if (address.length() == 0)
        {
            return false;
        }

        int octet;
        int octets = 0;
        
        string temp = address+".";

        int pos;
        int start = 0;
        while (start < temp.length()
            && (pos = temp.indexof('.', start)) > start)
        {
            if (octets == 4)
            {
                return false;
            }
            try
            {
                octet = integer.parseint(temp.substring(start, pos));
            }
            catch (numberformatexception ex)
            {
                return false;
            }
            if (octet < 0 || octet > 255)
            {
                return false;
            }
            start = pos + 1;
            octets++;
        }

        return octets == 4;
    }

    public static boolean isvalidipv4withnetmask(
        string address)
    {
        int index = address.indexof("/");
        string mask = address.substring(index + 1);

        return (index > 0) && isvalidipv4(address.substring(0, index))
                           && (isvalidipv4(mask) || ismaskvalue(mask, 32));
    }

    public static boolean isvalidipv6withnetmask(
        string address)
    {
        int index = address.indexof("/");
        string mask = address.substring(index + 1);

        return (index > 0) && (isvalidipv6(address.substring(0, index))
                           && (isvalidipv6(mask) || ismaskvalue(mask, 128)));
    }

    private static boolean ismaskvalue(string component, int size)
    {
        try
        {
            int value = integer.parseint(component);

            return value >= 0 && value <= size;
        }
        catch (numberformatexception e)
        {
            return false;
        }
    }

    /**
     * validate the given ipv6 address.
     *
     * @param address the ip address as a string.
     *
     * @return true if a valid ipv4 address, false otherwise
     */
    public static boolean isvalidipv6(
        string address)
    {
        if (address.length() == 0)
        {
            return false;
        }

        int octet;
        int octets = 0;

        string temp = address + ":";
        boolean doublecolonfound = false;
        int pos;
        int start = 0;
        while (start < temp.length()
            && (pos = temp.indexof(':', start)) >= start)
        {
            if (octets == 8)
            {
                return false;
            }

            if (start != pos)
            {
                string value = temp.substring(start, pos);

                if (pos == (temp.length() - 1) && value.indexof('.') > 0)
                {
                    if (!isvalidipv4(value))
                    {
                        return false;
                    }

                    octets++; // add an extra one as address covers 2 words.
                }
                else
                {
                    try
                    {
                        octet = integer.parseint(temp.substring(start, pos), 16);
                    }
                    catch (numberformatexception ex)
                    {
                        return false;
                    }
                    if (octet < 0 || octet > 0xffff)
                    {
                        return false;
                    }
                }
            }
            else
            {
                if (pos != 1 && pos != temp.length() - 1 && doublecolonfound)
                {
                    return false;
                }
                doublecolonfound = true;
            }
            start = pos + 1;
            octets++;
        }

        return octets == 8 || doublecolonfound;
    }
}


