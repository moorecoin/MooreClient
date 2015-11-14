package org.ripple.bouncycastle.asn1.x500;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;

/**
 * it turns out that the number of standard ways the fields in a dn should be 
 * encoded into their asn.1 counterparts is rapidly approaching the
 * number of machines on the internet. by default the x500name class
 * will produce utf8strings in line with the current recommendations (rfc 3280).
 * <p>
 */
public interface x500namestyle
{
    /**
     * convert the passed in string value into the appropriate asn.1
     * encoded object.
     * 
     * @param oid the oid associated with the value in the dn.
     * @param value the value of the particular dn component.
     * @return the asn.1 equivalent for the value.
     */
    asn1encodable stringtovalue(asn1objectidentifier oid, string value);

    /**
     * return the oid associated with the passed in name.
     *
     * @param attrname the string to match.
     * @return an oid
     */
    asn1objectidentifier attrnametooid(string attrname);

    /**
     * return an array of rdn generated from the passed in string.
     * @param dirname  the string representation.
     * @return  an array of corresponding rdns.
     */
    rdn[] fromstring(string dirname);

    /**
     * return true if the two names are equal.
     *
     * @param name1 first name for comparison.
     * @param name2 second name for comparison.
     * @return true if name1 = name 2, false otherwise.
     */
    boolean areequal(x500name name1, x500name name2);

    /**
     * calculate a hashcode for the passed in name.
     *
     * @param name the name the hashcode is required for.
     * @return the calculated hashcode.
     */
    int calculatehashcode(x500name name);

    /**
     * convert the passed in x500name to a string.
     * @param name the name to convert.
     * @return a string representation.
     */
    string tostring(x500name name);

    /**
     * return the display name for tostring() associated with the oid.
     *
     * @param oid  the oid of interest.
     * @return the name displayed in tostring(), null if no mapping provided.
     */
    string oidtodisplayname(asn1objectidentifier oid);

    /**
     * return the acceptable names in a string dn that map to oid.
     *
     * @param oid  the oid of interest.
     * @return an array of string aliases for the oid, zero length if there are none.
     */
    string[] oidtoattrnames(asn1objectidentifier oid);
}
