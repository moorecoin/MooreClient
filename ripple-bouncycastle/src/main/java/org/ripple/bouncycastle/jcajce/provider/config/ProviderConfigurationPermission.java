package org.ripple.bouncycastle.jcajce.provider.config;

import java.security.basicpermission;
import java.security.permission;
import java.util.stringtokenizer;

import org.ripple.bouncycastle.util.strings;

/**
 * a permission class to define what can be done with the configurableprovider interface.
 * <p>
 * available permissions are "threadlocalecimplicitlyca" and "ecimplicitlyca" which allow the setting
 * of the thread local and global ecimplicitlyca parameters respectively.
 * </p>
 * <p>
 * examples:
 * <ul>
 * <li>providerconfigurationpermission("bc"); // enable all permissions</li>
 * <li>providerconfigurationpermission("bc", "threadlocalecimplicitlyca"); // enable thread local only</li>
 * <li>providerconfigurationpermission("bc", "ecimplicitlyca"); // enable global setting only</li>
 * <li>providerconfigurationpermission("bc", "threadlocalecimplicitlyca, ecimplicitlyca"); // enable both explicitly</li>
 * </ul>
 * <p>
 * note: permission checks are only enforced if a security manager is present.
 * </p>
 */
public class providerconfigurationpermission
    extends basicpermission
{
    private static final int  thread_local_ec_implicitly_ca = 0x01;
    private static final int  ec_implicitly_ca = 0x02;
    private static final int  thread_local_dh_default_params = 0x04;
    private static final int  dh_default_params = 0x08;

    private static final int  all = thread_local_ec_implicitly_ca | ec_implicitly_ca | thread_local_dh_default_params | dh_default_params;

    private static final string thread_local_ec_implicitly_ca_str = "threadlocalecimplicitlyca";
    private static final string ec_implicitly_ca_str = "ecimplicitlyca";
    private static final string thread_local_dh_default_params_str = "threadlocaldhdefaultparams";
    private static final string dh_default_params_str = "dhdefaultparams";

    private static final string all_str = "all";

    private final string actions;
    private final int permissionmask;

    public providerconfigurationpermission(string name)
    {
        super(name);
        this.actions = "all";
        this.permissionmask = all;
    }

    public providerconfigurationpermission(string name, string actions)
    {
        super(name, actions);
        this.actions = actions;
        this.permissionmask = calculatemask(actions);
    }

    private int calculatemask(
        string actions)
    {
        stringtokenizer tok = new stringtokenizer(strings.tolowercase(actions), " ,");
        int             mask = 0;

        while (tok.hasmoretokens())
        {
            string s = tok.nexttoken();

            if (s.equals(thread_local_ec_implicitly_ca_str))
            {
                mask |= thread_local_ec_implicitly_ca;
            }
            else if (s.equals(ec_implicitly_ca_str))
            {
                mask |= ec_implicitly_ca;
            }
            else if (s.equals(thread_local_dh_default_params_str))
            {
                mask |= thread_local_dh_default_params;
            }
            else if (s.equals(dh_default_params_str))
            {
                mask |= dh_default_params;
            }
            else if (s.equals(all_str))
            {
                mask |= all;
            }
        }

        if (mask == 0)
        {
            throw new illegalargumentexception("unknown permissions passed to mask");
        }
        
        return mask;
    }

    public string getactions()
    {
        return actions;
    }

    public boolean implies(
        permission permission)
    {
        if (!(permission instanceof providerconfigurationpermission))
        {
            return false;
        }

        if (!this.getname().equals(permission.getname()))
        {
            return false;
        }
        
        providerconfigurationpermission other = (providerconfigurationpermission)permission;
        
        return (this.permissionmask & other.permissionmask) == other.permissionmask;
    }

    public boolean equals(
        object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (obj instanceof providerconfigurationpermission)
        {
            providerconfigurationpermission other = (providerconfigurationpermission)obj;

            return this.permissionmask == other.permissionmask && this.getname().equals(other.getname());
        }

        return false;
    }

    public int hashcode()
    {
        return this.getname().hashcode() + this.permissionmask;
    }
}
