package org.ripple.bouncycastle.jcajce.provider.config;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;

/**
 * implemented by the bc provider. this allows setting of hidden parameters,
 * such as the implicitca parameters from x.962, if used.
 */
public interface configurableprovider
{
    /**
     * elliptic curve ca parameters - thread local version
     */
    static final string thread_local_ec_implicitly_ca = "threadlocalecimplicitlyca";

    /**
     * elliptic curve ca parameters - thread local version
     */
    static final string ec_implicitly_ca = "ecimplicitlyca";

    /**
     * diffie-hellman default parameters - thread local version
     */
    static final string thread_local_dh_default_params = "threadlocaldhdefaultparams";

    /**
     * diffie-hellman default parameters - vm wide version
     */
    static final string dh_default_params = "dhdefaultparams";

    void setparameter(string parametername, object parameter);

    void addalgorithm(string key, string value);

    boolean hasalgorithm(string type, string name);

    void addkeyinfoconverter(asn1objectidentifier oid, asymmetrickeyinfoconverter keyinfoconverter);
}
