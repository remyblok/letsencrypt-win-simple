using System;
using System.Collections.Generic;
using System.IO;
using CommandLine;
using letsencrypt_webrole.Services;

namespace letsencrypt_webrole
{
	internal class Options
	{
		[Option(Required = true, HelpText = "Folder where to find/store the registration and certificates")]
		public string WorkingFolder { get; set; }

		[Option(Required = true, HelpText = "The hostname of the IIS website")]
		public string HostName { get; set; }

		[Option(Required = true, HelpText = "Password to secure the generated PFX files with")]
		public string PfxPassword { get; set; }

		[Option(HelpText = "Overrides BaseUri setting to https://acme-staging.api.letsencrypt.org/")]
		public bool TestMode { get; set; }

		[Option(HelpText = "Indication to renew certificate i.e. called from Scheduled task")]
		public bool Renew { get; set; }

		[Option(HelpText = "Install current certificate only, do not get a new cert")]
		public bool InstallOnly { get; set; }

		[Option(Default = 60, HelpText = "After how many days the certificate needs to be renewed")]
		public int RenewalDays { get; set; }

		[Option(HelpText = "Block HTTP traffic in firewall after installation of certificate")]
		public bool DoNotBlockHttp { get; set; }

		[Option(HelpText = "Set this to true to retain the challange file, otherwise it gets deleted")]
		public bool RetainChallangeFile { get; set; }

		[Option(HelpText = "Indidation that the working folder is a network drive that needs to be mapped first")]
		public bool ConnectWorkingFolderAsNetworkDrive { get; set; }

		[Option(HelpText = "User name for logging in to the network drive")]
		public string NetworkDriveUserName { get; set; }

		[Option(HelpText = "Password for logging in to the network drive")]
		public string NetworkDrivePassword { get; set; }

		public IReadOnlyDictionary<WellKnownFile, string> WellKnownFilePaths { get; private set; } = new Dictionary<WellKnownFile, string>();

		public string BaseUri { get; private set; }

		public string CertificateFolder { get; private set; }

		public void Initialize()
		{
			NetworkDriveService.MapWorkingFolder(this);

			if (!Directory.Exists(WorkingFolder))
				throw new DirectoryNotFoundException($"Directory '{WorkingFolder}' does not exist or cannot be accessed");

			CertificateFolder = Path.Combine(WorkingFolder, HostName);
			Directory.CreateDirectory(CertificateFolder);

			string logFileFolder = Path.Combine(CertificateFolder, "logs");
			Directory.CreateDirectory(logFileFolder);

			BaseUri = TestMode ? "https://acme-staging.api.letsencrypt.org/" : "https://acme-v01.api.letsencrypt.org/";

			WellKnownFilePaths = new Dictionary<WellKnownFile, string>
			{
				{WellKnownFile.KeyGen, Path.Combine(CertificateFolder, $"{HostName}-gen-key.json")},
				{WellKnownFile.KeyPem, Path.Combine(CertificateFolder, $"{HostName}-key.pem")},
				{WellKnownFile.CsrGen, Path.Combine(CertificateFolder, $"{HostName}-gen-csr.json")},
				{WellKnownFile.CsrPem, Path.Combine(CertificateFolder, $"{HostName}-csr.pem")},
				{WellKnownFile.CrtDer, Path.Combine(CertificateFolder, $"{HostName}-crt.der")},
				{WellKnownFile.CrtPem, Path.Combine(CertificateFolder, $"{HostName}-crt.pem") },
				{WellKnownFile.ChainPem, Path.Combine(CertificateFolder, $"{HostName}-chain.pem")},
				{WellKnownFile.CrtPfx, Path.Combine(CertificateFolder, $"{HostName}-all.pfx")},
				{WellKnownFile.AcmeSigner, Path.Combine(WorkingFolder, TestMode ? "staging" : "v01" , "Signer.xml")},
				{WellKnownFile.AcmeRegistration, Path.Combine(WorkingFolder, TestMode ? "staging" : "v01", "Registration.json")},
				{WellKnownFile.LogLocation, Path.Combine(logFileFolder, $"{DateTime.UtcNow:yyyyMMdd HHmmss}{(Renew ? " Renew" : InstallOnly ? " InstallOnly" : "")}.log")},
			};
		}
	}

	enum WellKnownFile
	{
		KeyGen,
		KeyPem,
		CsrGen,
		CsrPem,
		CrtDer,
		CrtPem,
		ChainPem,
		CrtPfx,
		AcmeSigner,
		AcmeRegistration,
		LogLocation,
	}
}