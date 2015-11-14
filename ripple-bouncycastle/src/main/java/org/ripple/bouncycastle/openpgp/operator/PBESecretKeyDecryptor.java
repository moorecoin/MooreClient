package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.bcpg.s2k;
import org.ripple.bouncycastle.openpgp.pgpexception;

public abstract class pbesecretkeydecryptor
{
    private char[] passphrase;
    private pgpdigestcalculatorprovider calculatorprovider;

    protected pbesecretkeydecryptor(char[] passphrase, pgpdigestcalculatorprovider calculatorprovider)
    {
        this.passphrase = passphrase;
        this.calculatorprovider = calculatorprovider;
    }

    public pgpdigestcalculator getchecksumcalculator(int hashalgorithm)
        throws pgpexception
    {
        return calculatorprovider.get(hashalgorithm);
    }

    public byte[] makekeyfrompassphrase(int keyalgorithm, s2k s2k)
        throws pgpexception
    {
        return pgputil.makekeyfrompassphrase(calculatorprovider, keyalgorithm, s2k, passphrase);
    }

    public abstract byte[] recoverkeydata(int encalgorithm, byte[] key, byte[] iv, byte[] keydata, int keyoff, int keylen)
        throws pgpexception;
}
