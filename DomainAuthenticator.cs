using System;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using DDomain = System.DirectoryServices.ActiveDirectory.Domain;

namespace Penguin.Authentication.Domain
{
    public class DomainAuthenticator
    {
        public string FullDomain { get; private set; }

        public string Domain { get; private set; }

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

        public DomainAuthenticator(string domain = null)
        {
            domain ??= ActiveDirectoryDomain;

            if (!domain.Contains('.'))
            {
                Domain = domain;

                FullDomain = $"{domain}.local";
            }
            else
            {
                FullDomain = domain;

                Domain = domain.Split('.')[0];
            }
        }

        public bool Authenticate(string userName, string password)
        {
            using PrincipalContext pc = new(ContextType.Domain, Domain);
            // validate the credentials
            return pc.ValidateCredentials(userName, password);
        }
    }
}