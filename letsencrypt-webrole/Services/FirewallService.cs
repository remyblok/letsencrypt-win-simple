using System;
using System.Linq;
using NetFwTypeLib;

namespace letsencrypt_webrole.Services
{
    class FirewallService
    {

        public void BlockHttpPort()
        {
            Log.Information("Blocking HTTP access in Firewall");

            INetFwRule rule = GetHttpPort();
            if (rule != null)
                rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
        }

        public void UnblockHttpPort()
        {
            Log.Information("Unblocking HTTP access in Firewall");

            INetFwRule rule = GetHttpPort();
            if (rule != null)
                rule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
        }

        private INetFwRule GetHttpPort()
        {
            INetFwPolicy2 fwPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            INetFwRule port80Rule = fwPolicy.Rules.OfType<INetFwRule>().FirstOrDefault(r => r.Protocol == 6 /* TCP */ && r.LocalPorts == "80");

            return port80Rule;
        }
    }
}
