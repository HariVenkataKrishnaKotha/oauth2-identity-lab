using Microsoft.Extensions.Hosting;

namespace ResourceApi.Services;

public sealed class JwksRefreshService : IHostedService, IDisposable
{
    private readonly JwksProvider _provider;
    private Timer? _timer;

    public JwksRefreshService(JwksProvider provider) => _provider = provider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Initial fetch on startup (with simple retry)
        var delay = TimeSpan.FromSeconds(1);
        for (var i = 0; i < 5; i++)
        {
            try
            {
                await _provider.RefreshAsync(cancellationToken);
                break;
            }
            catch
            {
                await Task.Delay(delay, cancellationToken);
                delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 30));
            }
        }

        // Refresh every 24h
        _timer = new Timer(async _ => {
            try { await _provider.RefreshAsync(); } catch { /* swallow */ }
        }, null, TimeSpan.FromHours(24), TimeSpan.FromHours(24));
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        return Task.CompletedTask;
    }

    public void Dispose() => _timer?.Dispose();
}
