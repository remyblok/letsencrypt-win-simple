using System;
using System.IO;
using System.Net;
using ACMESharp;
using ACMESharp.JOSE;

namespace letsencrypt_webrole.Services
{
    class AcmeClientService : IDisposable
    {
        private readonly Options _options;
        private readonly RS256Signer _signer;
        private readonly AcmeClient _client;

        private bool _isInitialized;

        public AcmeClientService(Options options)
        {
            _options = options;
            _signer = new RS256Signer();
            _client = new AcmeClient();
        }

        public void Initialize()
        {
            Log.Information("Initializing ACME client");

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

            if (!File.Exists(_options.WellKnownFilePaths[WellKnownFile.AcmeSigner]))
                throw new FileNotFoundException($"Signer file '{_options.WellKnownFilePaths[WellKnownFile.AcmeSigner]}' not found");
            if (!File.Exists(_options.WellKnownFilePaths[WellKnownFile.AcmeRegistration]))
                throw new FileNotFoundException($"Registration file '{_options.WellKnownFilePaths[WellKnownFile.AcmeRegistration]}' not found");

            _signer.Init();

            using (FileStream signerStream = File.OpenRead(_options.WellKnownFilePaths[WellKnownFile.AcmeSigner]))
                _signer.Load(signerStream);

            _client.Signer = _signer;
            _client.RootUrl = new Uri(_options.BaseUri);

            _client.Init();
            _client.GetDirectory(true);

            using (FileStream registrationStream = File.OpenRead(_options.WellKnownFilePaths[WellKnownFile.AcmeRegistration]))
                _client.Registration = AcmeRegistration.Load(registrationStream);

            _isInitialized = true;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            _signer.Dispose();
            _client.Dispose();
        }

        public AuthorizationStateHandler AuthorizeIdentifier(string targetHost)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("Need to call Initialze first");

            return new AuthorizationStateHandler(_client, _client.AuthorizeIdentifier(targetHost));
        }

        public CertificateRequest RequestCertificate(string csrContent)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("Need to call Initialze first");

            return _client.RequestCertificate(csrContent);
        }
    }
}
