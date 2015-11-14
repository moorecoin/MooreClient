package org.ripple.bouncycastle.jce.provider;

import java.util.date;

class certstatus
{
    public static final int unrevoked = 11;

    public static final int undetermined = 12;

    int certstatus = unrevoked;

    date revocationdate = null;

    /**
     * @return returns the revocationdate.
     */
    public date getrevocationdate()
    {
        return revocationdate;
    }

    /**
     * @param revocationdate the revocationdate to set.
     */
    public void setrevocationdate(date revocationdate)
    {
        this.revocationdate = revocationdate;
    }

    /**
     * @return returns the certstatus.
     */
    public int getcertstatus()
    {
        return certstatus;
    }

    /**
     * @param certstatus the certstatus to set.
     */
    public void setcertstatus(int certstatus)
    {
        this.certstatus = certstatus;
    }
}
