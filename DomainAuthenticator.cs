using Novell.Directory.Ldap;
using Penguin.Authentication.Abstractions;
using Penguin.Authentication.Abstractions.Interfaces;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using DDomain = System.DirectoryServices.ActiveDirectory.Domain;

namespace Penguin.Authentication.Domain
{
    public class DomainAuthenticator : IAuthenticator
    {
        public static string ActiveDirectoryDomain
        {
            get
            {
                if (activeDirectoryDomain is null)
                {
                    activeDirectoryDomain = string.Empty;

                    try
                    {
                        DDomain ddomain = DDomain.GetComputerDomain();
                        activeDirectoryDomain = ddomain.Name;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine(ex.Message);
                    }
                }

                return activeDirectoryDomain;
            }
        }

        private static string activeDirectoryDomain;

        public Task<AuthenticationResult> Authenticate(string username, string password, string domain = null)
        {
            domain ??= ActiveDirectoryDomain;

            try
            {
                using LdapConnection cn = new();

                cn.Connect(domain, 389);

                cn.Bind($"{domain.Split('.')[0]}\\{username}", password);

                return Task.FromResult(new AuthenticationResult()
                {
                    IsValid = true
                });
            }
            catch (Exception ex)
            {
                return Task.FromResult(new AuthenticationResult()
                {
                    IsValid = false,
                    Exception = ex
                });
            }
        }

    }
}

#if NET48
public static class StringExtensions
{
    public static bool Contains(this string s, char value)
    {
		if (s is null)
		{
			throw new ArgumentNullException(nameof(s));
		}

		return s.Contains($"{value}");
    }
}
#endif