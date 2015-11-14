package org.ripple.bouncycastle.asn1.isismtt.x509;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * monetary limit for transactions. the qceumonetarylimit qc statement must be
 * used in new certificates in place of the extension/attribute monetarylimit
 * since january 1, 2004. for the sake of backward compatibility with
 * certificates already in use, components should support monetarylimit (as well
 * as qceulimitvalue).
 * <p/>
 * indicates a monetary limit within which the certificate holder is authorized
 * to act. (this value does not express a limit on the liability of the
 * certification authority).
 * <p/>
 * <pre>
 *    monetarylimitsyntax ::= sequence
 *    {
 *      currency printablestring (size(3)),
 *      amount integer,
 *      exponent integer
 *    }
 * </pre>
 * <p/>
 * currency must be the iso code.
 * <p/>
 * value = amount锟?0*exponent
 */
public class monetarylimit
    extends asn1object
{
    derprintablestring currency;
    asn1integer amount;
    asn1integer exponent;

    public static monetarylimit getinstance(object obj)
    {
        if (obj == null || obj instanceof monetarylimit)
        {
            return (monetarylimit)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new monetarylimit(asn1sequence.getinstance(obj));
        }

        throw new illegalargumentexception("unknown object in getinstance");
    }

    private monetarylimit(asn1sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        enumeration e = seq.getobjects();
        currency = derprintablestring.getinstance(e.nextelement());
        amount = asn1integer.getinstance(e.nextelement());
        exponent = asn1integer.getinstance(e.nextelement());
    }

    /**
     * constructor from a given details.
     * <p/>
     * <p/>
     * value = amount锟?0^exponent
     *
     * @param currency the currency. must be the iso code.
     * @param amount   the amount
     * @param exponent the exponent
     */
    public monetarylimit(string currency, int amount, int exponent)
    {
        this.currency = new derprintablestring(currency, true);
        this.amount = new asn1integer(amount);
        this.exponent = new asn1integer(exponent);
    }

    public string getcurrency()
    {
        return currency.getstring();
    }

    public biginteger getamount()
    {
        return amount.getvalue();
    }

    public biginteger getexponent()
    {
        return exponent.getvalue();
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *    monetarylimitsyntax ::= sequence
     *    {
     *      currency printablestring (size(3)),
     *      amount integer,
     *      exponent integer
     *    }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();
        seq.add(currency);
        seq.add(amount);
        seq.add(exponent);

        return new dersequence(seq);
    }

}
