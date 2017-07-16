using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using ACMESharp;
using ACMESharp.ACME;
using ACMESharp.HTTP;
using ACMESharp.JOSE;
using ACMESharp.PKI;

namespace letsencrypt_webrole.Services
{
    class AcmeCertificateService
    {
        private readonly Options _options;
        private readonly AcmeClientService _acmeClient;
        private readonly IisService _iisService;

        public AcmeCertificateService(Options options, AcmeClientService acmeClient, IisService iisService)
        {
            _options = options;
            _acmeClient = acmeClient;
            _iisService = iisService;
        }


        public bool IsCurrentCertificateValid()
        {
            if (!File.Exists(_options.WellKnownFilePaths[WellKnownFile.CrtDer]))
                return false;

            Log.Information($"Validating current certificate {_options.WellKnownFilePaths[WellKnownFile.CrtDer]}");
            X509Certificate2 cert = new X509Certificate2(_options.WellKnownFilePaths[WellKnownFile.CrtDer]);
            bool isvalid = cert.NotBefore.AddDays(_options.RenewalDays) > DateTime.UtcNow;
            Log.Information($"certificat is {(isvalid ? "" : "NOT ")}valid. Renew at {cert.NotBefore.AddDays(_options.RenewalDays):yyyy-MM-dd}. Valid through {cert.NotAfter:yyyy-MM-dd}");
            return isvalid;
        }

        public void RetrieveNewCertificate()
        {
            Log.Information("Retrieve new certificate");

            Authorize();
            GetCertificate();
        }


        private void Authorize()
        {
            Log.Information($"Authorizing Identifier {_options.HostName} using challenge type {AcmeProtocol.CHALLENGE_TYPE_HTTP}");

            AuthorizationStateHandler authState = _acmeClient.AuthorizeIdentifier(_options.HostName);
            HttpChallenge httpChallenge = authState.DecodeChallenge();
            using (_iisService.CreateAuthorizationFile(httpChallenge))
            {
                Log.Information("Submitting answer");
                authState.SubmitChallengeAnswer();
            }
        }

        private void GetCertificate()
        {
            Log.Information("Requesting Certificate");

            using (CertificateProvider cp = CertificateProvider.GetProvider())
            {
                RsaPrivateKeyParams rsaPkp = new RsaPrivateKeyParams();

                PrivateKey rsaKeys = cp.GeneratePrivateKey(rsaPkp);
                CsrParams csrParams = new CsrParams
                {
                    Details = new CsrDetails
                    {
                        CommonName = _options.HostName,
                    },
                };

                Csr csr = cp.GenerateCsr(csrParams, rsaKeys, Crt.MessageDigest.SHA256);

                byte[] derRaw;
                using (MemoryStream bs = new MemoryStream())
                {
                    cp.ExportCsr(csr, EncodingFormat.DER, bs);
                    derRaw = bs.ToArray();
                }
                string derB64U = JwsHelper.Base64UrlEncode(derRaw);

                CertificateRequest certReq = _acmeClient.RequestCertificate(derB64U);

                if (certReq.StatusCode != HttpStatusCode.Created)
                    throw new Exception($"Request status = {certReq.StatusCode}");

                using (FileStream fs = new FileStream(_options.WellKnownFilePaths[WellKnownFile.KeyGen], FileMode.Create))
                    cp.SavePrivateKey(rsaKeys, fs);
                using (FileStream fs = new FileStream(_options.WellKnownFilePaths[WellKnownFile.KeyPem], FileMode.Create))
                    cp.ExportPrivateKey(rsaKeys, EncodingFormat.PEM, fs);
                using (FileStream fs = new FileStream(_options.WellKnownFilePaths[WellKnownFile.CsrGen], FileMode.Create))
                    cp.SaveCsr(csr, fs);
                using (FileStream fs = new FileStream(_options.WellKnownFilePaths[WellKnownFile.CsrPem], FileMode.Create))
                    cp.ExportCsr(csr, EncodingFormat.PEM, fs);

                Log.Information($"Saving Certificate to {_options.WellKnownFilePaths[WellKnownFile.CrtDer]}");
                using (FileStream file = File.Create(_options.WellKnownFilePaths[WellKnownFile.CrtDer]))
                    certReq.SaveCertificate(file);

                Crt crt;
                using (FileStream source = new FileStream(_options.WellKnownFilePaths[WellKnownFile.CrtDer], FileMode.Open),
                    target = new FileStream(_options.WellKnownFilePaths[WellKnownFile.CrtPem], FileMode.Create))
                {
                    crt = cp.ImportCertificate(EncodingFormat.DER, source);
                    cp.ExportCertificate(crt, EncodingFormat.PEM, target);
                }

                // To generate a PKCS#12 (.PFX) file, we need the issuer's public certificate
                string isuPemFile = GetIssuerCertificate(certReq, cp);

                using (FileStream intermediate = new FileStream(isuPemFile, FileMode.Open),
                    certificate = new FileStream(_options.WellKnownFilePaths[WellKnownFile.CrtPem], FileMode.Open),
                    chain = new FileStream(_options.WellKnownFilePaths[WellKnownFile.ChainPem], FileMode.Create))
                {
                    certificate.CopyTo(chain);
                    intermediate.CopyTo(chain);
                }

                Log.Information($"Saving Certificate to {_options.WellKnownFilePaths[WellKnownFile.CrtPfx]}");
                using (FileStream source = new FileStream(isuPemFile, FileMode.Open),
                    target = new FileStream(_options.WellKnownFilePaths[WellKnownFile.CrtPfx], FileMode.Create))
                {
                    Crt isuCrt = cp.ImportCertificate(EncodingFormat.PEM, source);
                    cp.ExportArchive(rsaKeys, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target, _options.PfxPassword);
                }
            }
        }


        private string GetIssuerCertificate(CertificateRequest certificate, CertificateProvider cp)
        {
            var linksEnum = certificate.Links;
            if (linksEnum == null)
                return null;

            LinkCollection links = new LinkCollection(linksEnum);
            Link upLink = links.GetFirstOrDefault("up");
            if (upLink == null)
                return null;

            string temporaryFileName = Path.GetTempFileName();
            try
            {
                using (WebClient web = new WebClient())
                {
                    Uri uri = new Uri(new Uri(_options.BaseUri), upLink.Uri);
                    web.DownloadFile(uri, temporaryFileName);
                }

                X509Certificate2 cacert = new X509Certificate2(temporaryFileName);
                string sernum = cacert.GetSerialNumberString();

                string cacertDerFile = Path.Combine(_options.CertificateFolder, $"ca-{sernum}-crt.der");
                string cacertPemFile = Path.Combine(_options.CertificateFolder, $"ca-{sernum}-crt.pem");

                File.Copy(temporaryFileName, cacertDerFile, true);

                Log.Information($"Saving Issuer Certificate to {cacertPemFile}");
                using (FileStream source = new FileStream(cacertDerFile, FileMode.Open),
                    target = new FileStream(cacertPemFile, FileMode.Create))
                {
                    Crt caCrt = cp.ImportCertificate(EncodingFormat.DER, source);
                    cp.ExportCertificate(caCrt, EncodingFormat.PEM, target);
                }
                return cacertPemFile;
            }
            finally
            {
                if (File.Exists(temporaryFileName))
                    File.Delete(temporaryFileName);
            }
        }

    }
}
