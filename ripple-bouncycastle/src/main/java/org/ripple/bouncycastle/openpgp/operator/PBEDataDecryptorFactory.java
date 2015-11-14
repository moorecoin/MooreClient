package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.bcpg.s2k;
import org.ripple.bouncycastle.openpgp.pgpexception;

public abstract class pbedatadecryptorfactory
    implements pgpdatadecryptorfactory
{
    private char[] passphrase;
    private pgpdigestcalculatorprovider calculatorprovider;

    protected pbedatadecryptorfactory(char[] passphrase, pgpdigestcalculatorprovider calculatorprovider)
    {
        this.passphrase = passphrase;
        this.calculatorprovider = calculatorprovider;
    }

    public byte[] makekeyfrompassphrase(int keyalgorithm, s2k s2k)
        throws pgpexception
    {
        return pgputil.makekeyfrompassphrase(calculatorprovider, keyalgorithm, s2k, passphrase);
    }

    public abstract byte[] recoversessiondata(int keyalgorithm, byte[] key, byte[] seckkeydata)
        throws pgpexception;
}
