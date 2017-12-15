using System;
using System.IO;
using System.Reflection;
using CommandLine;
using CommandLine.Text;
using letsencrypt_webrole.Services;

namespace letsencrypt_webrole
{
	public class Program
	{
		private readonly Options _options;
		private readonly AcmeClientService _acmeClient;
		private readonly IisService _iisService;
		private readonly AcmeCertificateService _acmeCertificateService;
		private readonly RenewalService _renewalService;
		private readonly CertificateStoreService _certificateStoreService;
		private readonly FirewallService _firewallService;

		private Program(Options options, AcmeClientService acmeClient, IisService iisService, AcmeCertificateService acmeCertificateService,
			RenewalService renewalService, CertificateStoreService certificateStoreService, FirewallService firewallService)
		{
			_options = options;
			_acmeClient = acmeClient;
			_iisService = iisService;
			_acmeCertificateService = acmeCertificateService;
			_renewalService = renewalService;
			_certificateStoreService = certificateStoreService;
			_firewallService = firewallService;
		}

		public static int Main(string[] args)
		{
			Log.PreInitialize();
			FixCosturaPath();

			Options options;
			if (!TryParseOptions(args, out options))
				return -1;

			AcmeClientService acmeClient = new AcmeClientService(options);
			FirewallService firewallService = new FirewallService();
			IisService iisService = new IisService(options, firewallService);
			AcmeCertificateService acmeCertificateService = new AcmeCertificateService(options, acmeClient, iisService);
			RenewalService renewalService = new RenewalService(options);
			CertificateStoreService certificateStoreService = new CertificateStoreService(options, iisService);

			Program program = new Program(options, acmeClient, iisService, acmeCertificateService, renewalService, certificateStoreService, firewallService);
			program.Execute();

			return 0;
		}

		private static void FixCosturaPath()
		{
			// need to fix the path of costura, 
			// because unmanaged dlls are expexted in "x64"-dir not in "64"-dir
			// or in "x86"-dir and not in "32"-dir

			Type assemblyLoaderType = Type.GetType("Costura.AssemblyLoader");
			FieldInfo tempField = assemblyLoaderType.GetField("tempBasePath", BindingFlags.NonPublic | BindingFlags.Static);
			string tempPath = (string)tempField.GetValue(null);

			string bitness = (IntPtr.Size == 8) ? "64" : "32";
			string xBitness = (IntPtr.Size == 8) ? "x64" : "x86";
			string old64Path = Path.Combine(tempPath, bitness);
			string x64Path = Path.Combine(tempPath, xBitness);

			if (Directory.Exists(x64Path))
				Directory.Delete(x64Path, true);

			if (Directory.Exists(old64Path))
				Directory.Move(old64Path, x64Path);
		}

		private void Execute()
		{
			Log.Initialize(_options);

			// no valid cert installed, no valid cert on disk => Authorize a new certificate
			// no valid cert installed, valid cert on disk => install current certificate
			// valid cert installed, less then 60 days old => no action
			// valid cert installed, more then 60 days old => Authorize a new certificate

			CertificateStatus status = _acmeCertificateService.IsCurrentCertificateValid();
			try
			{

				if (!_options.InstallOnly && status != CertificateStatus.OK)
				{
					_acmeClient.Initialize();
					_acmeCertificateService.RetrieveNewCertificate();
				}
			}
			catch (Exception e)
			{
				Log.Error(e.ToString());
			}
			finally
			{
				if (!_options.DoNotBlockHttp)
					_firewallService.BlockHttpPort();
			}

			_certificateStoreService.InstallCertificate(status);

			if (!_options.Renew)
				_renewalService.ScheduleRenewTask();
		}


		private static bool TryParseOptions(string[] args, out Options parsedOptions)
		{
			parsedOptions = null;
			var commandLineParseResult = Parser.Default.ParseArguments<Options>(args);

			if (commandLineParseResult.Tag == ParserResultType.NotParsed)
			{
				HelpText.AutoBuild(commandLineParseResult, current => HelpText.DefaultParsingErrorsHandler(commandLineParseResult, current), example => example);
				return false;
			}

			parsedOptions = ((Parsed<Options>)commandLineParseResult).Value;
			parsedOptions.Initialize();
			return true;
		}
	}
}
