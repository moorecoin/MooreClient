package org.ripple.bouncycastle.crypto.tls;

public class supplementaldataentry
{

    private int supp_data_type;
    private byte[] data;

    public supplementaldataentry(int supp_data_type, byte[] data)
    {
        this.supp_data_type = supp_data_type;
        this.data = data;
    }

    public int getdatatype()
    {
        return supp_data_type;
    }

    public byte[] getdata()
    {
        return data;
    }
}
