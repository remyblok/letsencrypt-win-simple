using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using ACMESharp.ACME;
using Microsoft.Web.Administration;
using Microsoft.Win32;

namespace letsencrypt_webrole.Services
{
	class IisService
	{
		private readonly Options _options;
		private readonly FirewallService _firewallService;

		private readonly Version _iisVersion;

		public IisService(Options options, FirewallService firewallService)
		{
			_options = options;
			_firewallService = firewallService;
			_iisVersion = GetIisVersion();
		}

		public ChallengeFile CreateAuthorizationFile(HttpChallenge httpChallenge)
		{
			if (httpChallenge.FilePath.StartsWith("/", StringComparison.OrdinalIgnoreCase))
				httpChallenge.FilePath = httpChallenge.FilePath.Substring(1);

			string webRootPath;
			using (ServerManager manager = new ServerManager())
			{
				Site site = GetSite(manager);
				webRootPath = site.Applications["/"].VirtualDirectories["/"].PhysicalPath;
			}

			string answerPath = Environment.ExpandEnvironmentVariables(Path.Combine(webRootPath, httpChallenge.FilePath));

			string directoryToDelete = null;
			if (!_options.RetainChallangeFile)
			{
				directoryToDelete = Path.GetDirectoryName(answerPath);
				while (Path.GetDirectoryName(directoryToDelete) != webRootPath && !Directory.Exists(directoryToDelete))
					directoryToDelete = Path.GetDirectoryName(directoryToDelete);
			}

			ChallengeFile file = null;
			try
			{
				file = new ChallengeFile(directoryToDelete)
				{
					Path = answerPath,
					Uri = new Uri(httpChallenge.FileUrl)
				};

				Log.Information($"Writing challenge answer to {answerPath}");
				string directory = Path.GetDirectoryName(answerPath);
				Debug.Assert(directory != null, "directory != null");
				Directory.CreateDirectory(directory);
				File.WriteAllText(answerPath, httpChallenge.FileContent);

				WriteWebConfig(directory);

				_firewallService.UnblockHttpPort();
				Warmup(file.Uri);

				Log.Information($"Answer should now be browsable at {file.Uri}");
				return file;
			}
			catch
			{
				file?.Dispose();
				throw;
			}
		}

		private void WriteWebConfig(string directory)
		{
			string webConfigPath = Path.Combine(directory, "web.config");
			string customWebConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "web_config.xml");
			if (File.Exists(customWebConfigPath))
			{
				Log.Information($"Writing custom web.config to add extensionless mime type to {webConfigPath}");
				File.Copy(customWebConfigPath, webConfigPath, true);
				return;
			}

			Log.Information($"Writing default web.config to add extensionless mime type to {webConfigPath}");

			Assembly executingAssembly = Assembly.GetExecutingAssembly();
			using (Stream manifestResourceStream = executingAssembly.GetManifestResourceStream("letsencrypt_webrole.Web_Config.xml"))
			using (FileStream webConfig = new FileStream(webConfigPath, FileMode.Create))
			{
				byte[] config = new byte[manifestResourceStream.Length];
				manifestResourceStream.Read(config, 0, config.Length);
				webConfig.Write(config, 0, config.Length);
			}
		}

		private void Warmup(Uri challengeUrl)
		{
			Log.Information($"Waiting for site to warmup by calling url {challengeUrl}");

			int retry = 0;
			while (true)
			{
				try
				{
					HttpWebRequest request = WebRequest.CreateHttp(challengeUrl);
					request.ServerCertificateValidationCallback += (s, certificate, chain, errors) => true;
					request.Timeout = (int)TimeSpan.FromMinutes(2).TotalMilliseconds;
					using (request.GetResponse())
					{
					}
					break;
				}
				catch (WebException) when (retry == 3)
				{
					break;
				}
				catch when (retry++ < 3)
				{
				}
			}
		}

		public void Install(X509Store store, X509Certificate2 certificate, bool recycleAppPool)
		{
			Log.Information("Apply certificate to HTTPS binding");
			using (ServerManager iisManager = new ServerManager())
			{
				Site site = GetSite(iisManager);

				Binding existingBinding = site.Bindings.FirstOrDefault(b => b.Host == _options.HostName && b.Protocol == "https")
											?? site.Bindings.FirstOrDefault(b => b.Protocol == "https");

				if (existingBinding != null)
				{
					if (existingBinding.CertificateStoreName == store.Name
						&& existingBinding.CertificateHash.SequenceEqual(certificate.GetCertHash()))
					{
						Log.Information("Existing https Binding already contrains correct certificate");
						return;
					}

					Log.Information("Updating Existing https Binding");
					Log.Information("IIS will serve the new certificate after the Application Pool Idle Timeout time has been reached.");

					existingBinding.CertificateStoreName = store.Name;
					existingBinding.CertificateHash = certificate.GetCertHash();
				}
				else
				{
					Log.Information("Adding https Binding");
					Binding existingHttpBinding = site.Bindings.FirstOrDefault(b => b.Host == _options.HostName && b.Protocol == "http")
												  ?? site.Bindings.FirstOrDefault(b => b.Protocol == "http");

					if (existingHttpBinding == null)
					{
						Log.Warning($"No HTTP binding for {_options.HostName} on {site.Name}");
					}
					else
					{
						//This had been a fix for the multiple site San cert, now it's just a precaution against erroring out
						string ip = GetIp(existingHttpBinding.EndPoint.ToString(), _options.HostName);

						Binding iisBinding = site.Bindings.Add(ip + ":443:" + _options.HostName, certificate.GetCertHash(), store.Name);
						iisBinding.Protocol = "https";

						if (_iisVersion.Major >= 8)
							iisBinding.SetAttributeValue("sslFlags", 1); // Enable SNI support
					}
				}

				Log.Information("Committing binding changes to IIS");
				iisManager.CommitChanges();

				if (recycleAppPool)
				{
					Log.Information($"Recycling app pool {site.Applications["/"].ApplicationPoolName}");
					iisManager.ApplicationPools.First(a => a.Name == site.Applications["/"].ApplicationPoolName).Recycle();
				}
			}
		}

		private Site GetSite(ServerManager iisManager)
		{
			return iisManager.Sites.FirstOrDefault(s => s.Bindings.Any(b => b.Host == _options.HostName))
				   ?? iisManager.Sites.FirstOrDefault()
				   ?? throw new InvalidOperationException("No site could be found in IIS");
		}

		private string GetIp(string httpEndpoint, string host)
		{
			string ip = "*";
			string httpIp = httpEndpoint.Remove(httpEndpoint.IndexOf(':'), httpEndpoint.Length - httpEndpoint.IndexOf(':'));

			if (_iisVersion.Major >= 8 && httpIp != "0.0.0.0")
			{
				Log.Warning($"Warning creating HTTPS Binding for {host}.");
				//Console.WriteLine(
				//    "The HTTP binding is IP specific; the app can create it. However, if you have other HTTPS sites they will all get an invalid certificate error until you manually edit one of their HTTPS bindings.");
				//Console.WriteLine("\r\nYou need to edit the binding, turn off SNI, click OK, edit it again, enable SNI and click OK. That should fix the error.");
				//Console.WriteLine("\r\nOtherwise, manually create the HTTPS binding and rerun the application.");
				//Console.WriteLine("\r\nYou can see https://github.com/Lone-Coder/letsencrypt-win-simple/wiki/HTTPS-Binding-With-Specific-IP for more information.");
				//Console.WriteLine(
				//    "\r\nPress Y to acknowledge this and continue. Press any other key to stop installing the certificate");
				ip = httpIp;
			}
			else if (httpIp != "0.0.0.0")
			{
				ip = httpIp;
			}
			return ip;
		}

		private Version GetIisVersion()
		{
			using (RegistryKey componentsKey = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\InetStp", false))
			{
				if (componentsKey != null)
				{
					int majorVersion = (int)componentsKey.GetValue("MajorVersion", -1);
					int minorVersion = (int)componentsKey.GetValue("MinorVersion", -1);

					if (majorVersion != -1 && minorVersion != -1)
					{
						return new Version(majorVersion, minorVersion);
					}
				}

				return new Version(0, 0);
			}
		}
	}

	class ChallengeFile : IDisposable
	{
		private readonly string _folderToDelete;

		public ChallengeFile(string folderToDelete)
		{
			_folderToDelete = folderToDelete;
		}

		public Uri Uri { get; set; }
		public string Path { get; set; }

		/// <inheritdoc />
		public void Dispose()
		{
			if (!string.IsNullOrEmpty(_folderToDelete))
			{
				Log.Information($"Removing challage directory {_folderToDelete}");
				int retry = 0;

				while (true)
				{
					try
					{
						Directory.Delete(_folderToDelete, true);
						break;
					}
					catch (IOException) when (retry++ < 3)
					{
						Thread.Sleep(1000);
					}
				}
			}
		}
	}
}
