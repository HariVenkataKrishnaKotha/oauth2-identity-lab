using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Forwarder;

namespace Gateway.Infrastructure;

/// <summary>
/// Custom HttpClient factory for YARP Forwarder that can attach a client certificate per cluster (mTLS)
/// and tune the SocketsHttpHandler. Uses cluster Metadata keys:
///   - ClientCertPath
///   - ClientCertPassword
/// </summary>
public sealed class MtlsForwarderHttpClientFactory : IForwarderHttpClientFactory
{
    private readonly ILogger<MtlsForwarderHttpClientFactory> _log;

    public MtlsForwarderHttpClientFactory(ILogger<MtlsForwarderHttpClientFactory> log) => _log = log;

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        var handler = new SocketsHttpHandler
        {
            // Match YARP defaults (see docs) + a bit of tuning
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            ConnectTimeout = TimeSpan.FromSeconds(5),
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.Online
            }
        };

        // Attach cluster-specific client certificate if configured
        try
        {
            var meta = context.NewMetadata; // <-- YARP 2.3: use NewMetadata
            if (meta is not null &&
                meta.TryGetValue("ClientCertPath", out var pfx) &&
                !string.IsNullOrWhiteSpace(pfx))
            {
                meta.TryGetValue("ClientCertPassword", out var pwd);
                var cert = new X509Certificate2(pfx!, pwd, X509KeyStorageFlags.MachineKeySet);
                handler.SslOptions.ClientCertificates = new X509CertificateCollection { cert };
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed attaching client certificate. ClusterId={ClusterId}", context.ClusterId);
        }

        // If you want retries/circuit-breaker, see the note at the end (Resilience handler).
        return new HttpMessageInvoker(handler, disposeHandler: true);
    }
}
