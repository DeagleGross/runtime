// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.X509Certificates.Tests.Common;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace System.Net.Security.Tests
{
    using Configuration = System.Net.Test.Common.Configuration;

    public static class SslStreamCertificateContextTests
    {
        [Fact]
        [OuterLoop("Subject to resource contention and load.")]
        [PlatformSpecific(TestPlatforms.Linux)]
        public static async Task Create_OcspDoesNotReturnOrCacheInvalidStapleData()
        {
            string serverName = $"{nameof(Create_OcspDoesNotReturnOrCacheInvalidStapleData)}.example";

            CertificateAuthority.BuildPrivatePki(
                PkiOptions.EndEntityRevocationViaOcsp | PkiOptions.CrlEverywhere,
                out RevocationResponder responder,
                out CertificateAuthority rootAuthority,
                out CertificateAuthority[] intermediateAuthorities,
                out X509Certificate2 serverCert,
                testName: nameof(Create_OcspDoesNotReturnOrCacheInvalidStapleData),
                intermediateAuthorityCount: 1,
                subjectName: serverName,
                keyFactory: CertificateAuthority.KeyFactory.RSASize(2048),
                extensions: Configuration.Certificates.BuildTlsServerCertExtensions(serverName));

            using (responder)
            using (rootAuthority)
            using (CertificateAuthority intermediateAuthority = intermediateAuthorities[0])
            using (serverCert)
            using (X509Certificate2 rootCert = rootAuthority.CloneIssuerCert())
            using (X509Certificate2 issuerCert = intermediateAuthority.CloneIssuerCert())
            {
                responder.RespondKind = RespondKind.Invalid;

                SslStreamCertificateContext context = SslStreamCertificateContext.Create(
                    serverCert,
                    additionalCertificates: new X509Certificate2Collection { issuerCert },
                    offline: false);

                MethodInfo fetchOcspAsyncMethod = typeof(SslStreamCertificateContext).GetMethod(
                    "DownloadOcspAsync",
                    BindingFlags.Instance | BindingFlags.NonPublic);
                FieldInfo ocspResponseField = typeof(SslStreamCertificateContext).GetField(
                    "_ocspResponse",
                    BindingFlags.Instance | BindingFlags.NonPublic);

                Assert.NotNull(fetchOcspAsyncMethod);
                Assert.NotNull(ocspResponseField);

                byte[] ocspFetch = await (ValueTask<byte[]>)fetchOcspAsyncMethod.Invoke(context, Array.Empty<object>());
                Assert.Null(ocspFetch);

                byte[] ocspResponseValue = (byte[])ocspResponseField.GetValue(context);
                Assert.Null(ocspResponseValue);
            }
        }

        public enum AiaDisableMode
        {
            None,
            ChainPolicy,
            ChainPolicyWithSelectionCallback,
            OfflineCertificateContext,
        }

        // The server certificate is issued by an intermediate that is neither shipped with the certificate nor installed
        // anywhere, so the only way to obtain it is to download it from the AIA URL embedded in the leaf certificate.
        // See AIA-Disable.md for details.
        [Theory]
        [PlatformSpecific(TestPlatforms.Windows)]
        [InlineData(AiaDisableMode.None, true)]
        [InlineData(AiaDisableMode.ChainPolicy, false)]
        [InlineData(AiaDisableMode.ChainPolicyWithSelectionCallback, false)]
        [InlineData(AiaDisableMode.OfflineCertificateContext, false)]
        public static async Task ServerCertificate_AiaDownload_HonorsDisableCertificateDownloads(AiaDisableMode mode, bool expectAiaDownload)
        {
            using AiaServer aia = new AiaServer();
            string pathPrefix = $"/{Guid.NewGuid():N}";

            using X509Certificate2 root = CreateAiaTestCa("CN=AIA Test Root", issuer: null, aiaUrl: null);
            using X509Certificate2 intermediate = CreateAiaTestCa("CN=AIA Test Intermediate", root, aia.GetUrl($"{pathPrefix}/root.cer"));
            using X509Certificate2 leafWithEphemeralKey = CreateAiaTestLeaf(intermediate, aia.GetUrl($"{pathPrefix}/intermediate.cer"));
            aia.Serve($"{pathPrefix}/root.cer", root.RawData);
            aia.Serve($"{pathPrefix}/intermediate.cer", intermediate.RawData);

            // Windows requires a non-ephemeral key. Importing a leaf-only PFX also guarantees no chain travels with the certificate.
            using X509Certificate2 leaf = X509CertificateLoader.LoadPkcs12(
                leafWithEphemeralKey.Export(X509ContentType.Pfx, "pw"), "pw", X509KeyStorageFlags.DefaultKeySet);

            SslServerAuthenticationOptions serverOptions = new SslServerAuthenticationOptions();
            switch (mode)
            {
                case AiaDisableMode.None:
                    serverOptions.ServerCertificate = leaf;
                    break;
                case AiaDisableMode.ChainPolicy:
                    serverOptions.ServerCertificate = leaf;
                    serverOptions.CertificateChainPolicy = new X509ChainPolicy { DisableCertificateDownloads = true };
                    break;
                case AiaDisableMode.ChainPolicyWithSelectionCallback:
                    serverOptions.ServerCertificateSelectionCallback = (_, _) => leaf;
                    serverOptions.CertificateChainPolicy = new X509ChainPolicy { DisableCertificateDownloads = true };
                    break;
                case AiaDisableMode.OfflineCertificateContext:
                    serverOptions.ServerCertificateContext = SslStreamCertificateContext.Create(leaf, additionalCertificates: null, offline: true);
                    break;
            }

            // The client must not download anything itself, otherwise it would be indistinguishable from the server.
            SslClientAuthenticationOptions clientOptions = new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
                CertificateChainPolicy = new X509ChainPolicy
                {
                    DisableCertificateDownloads = true,
                    RevocationMode = X509RevocationMode.NoCheck,
                    VerificationFlags = X509VerificationFlags.AllFlags,
                },
            };

            using X509Store caStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            caStore.Open(OpenFlags.ReadWrite);

            try
            {
                (NetworkStream clientStream, NetworkStream serverStream) = await CreateConnectedStreamsAsync();
                using (clientStream)
                using (serverStream)
                using (SslStream client = new SslStream(clientStream))
                using (SslStream server = new SslStream(serverStream))
                {
                    await Task.WhenAll(
                        client.AuthenticateAsClientAsync(clientOptions),
                        server.AuthenticateAsServerAsync(serverOptions)).WaitAsync(TimeSpan.FromSeconds(30));
                }

                if (expectAiaDownload)
                {
                    Assert.True(aia.Requests.Count > 0, "Expected the control scenario to download the intermediate over AIA.");
                }
                else
                {
                    Assert.True(aia.Requests.Count == 0, $"Unexpected AIA requests: {string.Join(", ", aia.Requests)}");
                    Assert.Empty(caStore.Certificates.Find(X509FindType.FindByThumbprint, intermediate.Thumbprint, validOnly: false));
                }
            }
            finally
            {
                // .NET adds downloaded intermediates to the CurrentUser CA store on Windows, do not leave them behind.
                caStore.Remove(intermediate);
                caStore.Remove(root);
            }
        }

        private static async Task<(NetworkStream, NetworkStream)> CreateConnectedStreamsAsync()
        {
            using TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            TcpClient client = new TcpClient();
            Task connect = client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            TcpClient accepted = await listener.AcceptTcpClientAsync();
            await connect;

            return (client.GetStream(), accepted.GetStream());
        }

        private static X509Certificate2 CreateAiaTestCa(string subject, X509Certificate2 issuer, string aiaUrl)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, issuer is not null, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            if (aiaUrl is not null)
            {
                request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(null, new[] { aiaUrl }));
            }

            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddHours(-1);

            if (issuer is null)
            {
                return request.CreateSelfSigned(notBefore, notBefore.AddDays(2));
            }

            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            using X509Certificate2 publicOnly = request.Create(issuer, notBefore, issuer.NotAfter.AddMinutes(-10), RandomNumberGenerator.GetBytes(16));
            return publicOnly.CopyWithPrivateKey(key);
        }

        private static X509Certificate2 CreateAiaTestLeaf(X509Certificate2 issuer, string aiaUrl)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(null, new[] { aiaUrl }));

            SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost");
            request.CertificateExtensions.Add(san.Build());

            using X509Certificate2 publicOnly = request.Create(issuer, DateTimeOffset.UtcNow.AddHours(-1), issuer.NotAfter.AddMinutes(-5), RandomNumberGenerator.GetBytes(16));
            return publicOnly.CopyWithPrivateKey(key);
        }

        // Minimal HTTP server that serves AIA certificates and records every request.
        private sealed class AiaServer : IDisposable
        {
            private readonly TcpListener _listener = new TcpListener(IPAddress.Loopback, 0);
            private readonly Dictionary<string, byte[]> _content = new Dictionary<string, byte[]>();
            private readonly List<string> _requests = new List<string>();
            private readonly CancellationTokenSource _cts = new CancellationTokenSource();

            public AiaServer()
            {
                _listener.Start();
                _ = AcceptLoopAsync();
            }

            public List<string> Requests
            {
                get
                {
                    lock (_requests)
                    {
                        return new List<string>(_requests);
                    }
                }
            }

            public string GetUrl(string path) => $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}{path}";

            public void Serve(string path, byte[] body)
            {
                lock (_content)
                {
                    _content[path] = body;
                }
            }

            private async Task AcceptLoopAsync()
            {
                try
                {
                    while (true)
                    {
                        TcpClient client = await _listener.AcceptTcpClientAsync(_cts.Token);
                        _ = HandleAsync(client);
                    }
                }
                catch (Exception)
                {
                    // Listener stopped.
                }
            }

            private async Task HandleAsync(TcpClient client)
            {
                using (client)
                {
                    try
                    {
                        NetworkStream stream = client.GetStream();
                        byte[] buffer = new byte[4096];
                        int read = await stream.ReadAsync(buffer, _cts.Token);
                        string path = Encoding.ASCII.GetString(buffer, 0, read).Split(' ')[1];

                        lock (_requests)
                        {
                            _requests.Add(path);
                        }

                        byte[] body;
                        lock (_content)
                        {
                            body = _content.TryGetValue(path, out byte[] found) ? found : Array.Empty<byte>();
                        }

                        string status = body.Length > 0 ? "200 OK" : "404 Not Found";
                        await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Type: application/pkix-cert\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
                        await stream.WriteAsync(body);
                    }
                    catch (Exception)
                    {
                    }
                }
            }

            public void Dispose()
            {
                _cts.Cancel();
                _listener.Stop();
            }
        }
    }
}
