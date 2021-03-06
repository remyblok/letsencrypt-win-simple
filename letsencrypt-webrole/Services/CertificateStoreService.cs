﻿using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace letsencrypt_webrole.Services
{
	class CertificateStoreService
	{
		private readonly Options _options;
		private readonly IisService _iisService;

		public CertificateStoreService(Options options, IisService iisService)
		{
			_options = options;
			_iisService = iisService;
		}


		public void InstallCertificate(CertificateStatus statusPreviousCertificate)
		{
			if (!File.Exists(_options.WellKnownFilePaths[WellKnownFile.CrtPfx]))
			{
				Log.Error("Certificate to install not found!");
				return;
			}

			Log.Information("Installing certificate in store");

			X509Store store = null;
			X509Certificate2 newCertificate = null;
			X509Certificate2 knownCertificate = null;

			try
			{
				store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
				store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

				Log.Information($"Opened Certificate Store {store.Name}");

				X509KeyStorageFlags flags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;

				// See http://paulstovell.com/blog/x509certificate2
				newCertificate = new X509Certificate2(_options.WellKnownFilePaths[WellKnownFile.CrtPfx], _options.PfxPassword, flags)
				{
					FriendlyName = $"{_options.HostName} {(_options.TestMode ? "FAKE " : "")}{DateTime.UtcNow:O}"
				};

				knownCertificate = store.Certificates.OfType<X509Certificate2>().FirstOrDefault(c => c.Thumbprint == newCertificate.Thumbprint);

				if (knownCertificate != null)
				{
					Log.Information($"Certificate already in the Store {knownCertificate.FriendlyName}");
				}
				else
				{
					Log.Information($"Adding Certificate to Store {newCertificate.FriendlyName}");
					store.Add(newCertificate);
					knownCertificate = newCertificate;
				}

				bool needsRecycle = !_options.Renew || statusPreviousCertificate == CertificateStatus.NotFound;
				_iisService.Install(store, knownCertificate, needsRecycle);
			}
			finally
			{
				Log.Information("Closing Certificate Store");
				IDisposable disposable = newCertificate as IDisposable;
				disposable?.Dispose();
				disposable = knownCertificate as IDisposable;
				disposable?.Dispose();
				store?.Close();
			}
		}
	}
}
