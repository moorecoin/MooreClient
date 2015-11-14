package org.ripple.bouncycastle.util.io.pem;

public class pemheader
{
    private string name;
    private string value;

    public pemheader(string name, string value)
    {
        this.name = name;
        this.value = value;
    }

    public string getname()
    {
        return name;
    }

    public string getvalue()
    {
        return value;
    }

    public int hashcode()
    {
        return gethashcode(this.name) + 31 * gethashcode(this.value);    
    }

    public boolean equals(object o)
    {
        if (!(o instanceof pemheader))
        {
            return false;
        }

        pemheader other = (pemheader)o;

        return other == this || (isequal(this.name, other.name) && isequal(this.value, other.value));
    }

    private int gethashcode(string s)
    {
        if (s == null)
        {
            return 1;
        }

        return s.hashcode();
    }

    private boolean isequal(string s1, string s2)
    {
        if (s1 == s2)
        {
            return true;
        }

        if (s1 == null || s2 == null)
        {
            return false;
        }

        return s1.equals(s2);
    }

}
