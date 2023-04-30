using Penguin.Authentication.Abstractions;
using Penguin.Authentication.Abstractions.Interfaces;
using System;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Net;
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

			if (!domain.Contains('.'))
			{
				domain = domain.Split('.')[0];
			}

			using PrincipalContext pc = new(ContextType.Domain, domain);

            // validate the credentials
            return Task.FromResult(new AuthenticationResult()
            {
                IsValid = pc.ValidateCredentials(username, password)
            });
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