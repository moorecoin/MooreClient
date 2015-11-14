package org.ripple.bouncycastle.jce.provider;

import java.security.permission;

import javax.crypto.spec.dhparameterspec;

import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ec5util;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.config.providerconfiguration;
import org.ripple.bouncycastle.jcajce.provider.config.providerconfigurationpermission;
import org.ripple.bouncycastle.jce.spec.ecparameterspec;

class bouncycastleproviderconfiguration
    implements providerconfiguration
{
    private static permission bc_ec_local_permission = new providerconfigurationpermission(
        bouncycastleprovider.provider_name, configurableprovider.thread_local_ec_implicitly_ca);
    private static permission bc_ec_permission = new providerconfigurationpermission(
        bouncycastleprovider.provider_name, configurableprovider.ec_implicitly_ca);
    private static permission bc_dh_local_permission = new providerconfigurationpermission(
        bouncycastleprovider.provider_name, configurableprovider.thread_local_dh_default_params);
    private static permission bc_dh_permission = new providerconfigurationpermission(
        bouncycastleprovider.provider_name, configurableprovider.dh_default_params);

    private threadlocal ecthreadspec = new threadlocal();
    private threadlocal dhthreadspec = new threadlocal();

    private volatile ecparameterspec ecimplicitcaparams;
    private volatile object dhdefaultparams;

    void setparameter(string parametername, object parameter)
    {
        securitymanager securitymanager = system.getsecuritymanager();

        if (parametername.equals(configurableprovider.thread_local_ec_implicitly_ca))
        {
            ecparameterspec curvespec;

            if (securitymanager != null)
            {
                securitymanager.checkpermission(bc_ec_local_permission);
            }

            if (parameter instanceof ecparameterspec || parameter == null)
            {
                curvespec = (ecparameterspec)parameter;
            }
            else  // assume java.security.spec
            {
                curvespec = ec5util.convertspec((java.security.spec.ecparameterspec)parameter, false);
            }

            if (curvespec == null)
            {
                ecthreadspec.remove();
            }
            else
            {
                ecthreadspec.set(curvespec);
            }
        }
        else if (parametername.equals(configurableprovider.ec_implicitly_ca))
        {
            if (securitymanager != null)
            {
                securitymanager.checkpermission(bc_ec_permission);
            }

            if (parameter instanceof ecparameterspec || parameter == null)
            {
                ecimplicitcaparams = (ecparameterspec)parameter;
            }
            else  // assume java.security.spec
            {
                ecimplicitcaparams = ec5util.convertspec((java.security.spec.ecparameterspec)parameter, false);
            }
        }
        else if (parametername.equals(configurableprovider.thread_local_dh_default_params))
        {
            object dhspec;

            if (securitymanager != null)
            {
                securitymanager.checkpermission(bc_dh_local_permission);
            }

            if (parameter instanceof dhparameterspec || parameter instanceof dhparameterspec[] || parameter == null)
            {
                dhspec = parameter;
            }
            else
            {
                throw new illegalargumentexception("not a valid dhparameterspec");
            }

            if (dhspec == null)
            {
                dhthreadspec.remove();
            }
            else
            {
                dhthreadspec.set(dhspec);
            }
        }
        else if (parametername.equals(configurableprovider.dh_default_params))
        {
            if (securitymanager != null)
            {
                securitymanager.checkpermission(bc_dh_permission);
            }

            if (parameter instanceof dhparameterspec || parameter instanceof dhparameterspec[] || parameter == null)
            {
                dhdefaultparams = parameter;
            }
            else
            {
                throw new illegalargumentexception("not a valid dhparameterspec or dhparameterspec[]");
            }
        }
    }

    public ecparameterspec getecimplicitlyca()
    {
        ecparameterspec spec = (ecparameterspec)ecthreadspec.get();

        if (spec != null)
        {
            return spec;
        }

        return ecimplicitcaparams;
    }

    public dhparameterspec getdhdefaultparameters(int keysize)
    {
        object params = dhthreadspec.get();
        if (params == null)
        {
            params = dhdefaultparams;
        }

        if (params instanceof dhparameterspec)
        {
            dhparameterspec spec = (dhparameterspec)params;

            if (spec.getp().bitlength() == keysize)
            {
                return spec;
            }
        }
        else if (params instanceof dhparameterspec[])
        {
            dhparameterspec[] specs = (dhparameterspec[])params;

            for (int i = 0; i != specs.length; i++)
            {
                if (specs[i].getp().bitlength() == keysize)
                {
                    return specs[i];
                }
            }
        }

        return null;
    }
}
