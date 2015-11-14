package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public final class protocolversion
{

    public static final protocolversion sslv3 = new protocolversion(0x0300, "ssl 3.0");
    public static final protocolversion tlsv10 = new protocolversion(0x0301, "tls 1.0");
    public static final protocolversion tlsv11 = new protocolversion(0x0302, "tls 1.1");
    public static final protocolversion tlsv12 = new protocolversion(0x0303, "tls 1.2");
    public static final protocolversion dtlsv10 = new protocolversion(0xfeff, "dtls 1.0");
    public static final protocolversion dtlsv12 = new protocolversion(0xfefd, "dtls 1.2");

    private int version;
    private string name;

    private protocolversion(int v, string name)
    {
        this.version = v & 0xffff;
        this.name = name;
    }

    public int getfullversion()
    {
        return version;
    }

    public int getmajorversion()
    {
        return version >> 8;
    }

    public int getminorversion()
    {
        return version & 0xff;
    }

    public boolean isdtls()
    {
        return getmajorversion() == 0xfe;
    }

    public boolean isssl()
    {
        return this == sslv3;
    }

    public protocolversion getequivalenttlsversion()
    {
        if (!isdtls())
        {
            return this;
        }
        if (this == dtlsv10)
        {
            return tlsv11;
        }
        return tlsv12;
    }

    public boolean isequalorearlierversionof(protocolversion version)
    {
        if (getmajorversion() != version.getmajorversion())
        {
            return false;
        }
        int diffminorversion = version.getminorversion() - getminorversion();
        return isdtls() ? diffminorversion <= 0 : diffminorversion >= 0;
    }

    public boolean islaterversionof(protocolversion version)
    {
        if (getmajorversion() != version.getmajorversion())
        {
            return false;
        }
        int diffminorversion = version.getminorversion() - getminorversion();
        return isdtls() ? diffminorversion > 0 : diffminorversion < 0;
    }

    public boolean equals(object obj)
    {
        return this == obj;
    }

    public int hashcode()
    {
        return version;
    }

    public static protocolversion get(int major, int minor)
        throws ioexception
    {
        switch (major)
        {
        case 0x03:
            switch (minor)
            {
            case 0x00:
                return sslv3;
            case 0x01:
                return tlsv10;
            case 0x02:
                return tlsv11;
            case 0x03:
                return tlsv12;
            }
        case 0xfe:
            switch (minor)
            {
            case 0xff:
                return dtlsv10;
            case 0xfd:
                return dtlsv12;
            }
        }

        throw new tlsfatalalert(alertdescription.illegal_parameter);
    }

    public string tostring()
    {
        return name;
    }
}
