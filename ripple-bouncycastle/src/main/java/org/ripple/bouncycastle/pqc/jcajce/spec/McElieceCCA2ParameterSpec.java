package org.ripple.bouncycastle.pqc.jcajce.spec;


import java.security.spec.algorithmparameterspec;

/**
 * this class provides a specification for the parameters of the cca2-secure
 * variants of the mceliece pkcs that are used with
 * {@link mceliecefujisakicipher}, {@link mceliecekobaraimaicipher}, and
 * {@link mceliecepointchevalcipher}.
 *
 * @see mceliecefujisakicipher
 * @see mceliecekobaraimaicipher
 * @see mceliecepointchevalcipher
 */
public class mceliececca2parameterspec
    implements algorithmparameterspec
{

    /**
     * the default message digest ("sha256").
     */
    public static final string default_md = "sha256";

    private string mdname;

    /**
     * construct the default parameters. choose the
     */
    public mceliececca2parameterspec()
    {
        this(default_md);
    }

    /**
     * constructor.
     *
     * @param mdname the name of the hash function
     */
    public mceliececca2parameterspec(string mdname)
    {
        // check whether message digest is available
        // todo: this method not used!
//        try {
//            registry.getmessagedigest(mdname);
//        } catch (nosuchalgorithmexception nsae) {
//            throw new invalidparameterexception("message digest '" + mdname
//                    + "' not found'.");
//        }

        // assign message digest name
        this.mdname = mdname;
    }

    /**
     * @return the name of the hash function
     */
    public string getmdname()
    {
        return mdname;
    }

}
