using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// Alerts &amp; Evidence: how CryptoKey tells you something happened —
/// on-screen notifications, sounds, a webcam snapshot of whoever tripped
/// it, and a webhook to your phone.
/// </summary>
internal sealed class AlertsPage : Page
{
    private readonly ToggleSwitch _notify;
    private readonly ToggleSwitch _sounds;
    private readonly ToggleSwitch _webcam;
    private readonly Image _thumb = new() { Stretch = Stretch.UniformToFill };
    private readonly Border _thumbBox;
    private readonly TextBlock _capNote = Kit.Txt("", "caption", "dim");
    private readonly TextBox _url = new() { Watermark = "https://ntfy.sh/my-cryptokey", Width = 340 };
    private readonly DispatcherTimer _urlSave = new() { Interval = TimeSpan.FromMilliseconds(600) };
    private bool _syncing;

    public AlertsPage(PageContext ctx) : base(ctx)
    {
        PlatformCapabilities caps = ctx.Caps;
        _notify = Kit.Toggle(false, on => Set(g => g.BalloonTips = on));
        _sounds = Kit.Toggle(false, on => Set(g => g.Sounds = on));
        _webcam = Kit.Toggle(false, on => { Set(g => g.WebcamOnTamper = on); RefreshCapture(); });

        _thumbBox = new Border
        {
            Width = 176, Height = 110,
            CornerRadius = new CornerRadius(10),
            ClipToBounds = true,
            Background = Palette.CarbonDeep,
            BorderBrush = Palette.Hairline,
            BorderThickness = new Thickness(1),
            Child = new Grid
            {
                Children =
                {
                    new Icon(IconData.Camera, 26) { Foreground = Palette.TextFaint,
                        HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
                        VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center },
                    _thumb,
                },
            },
        };

        var captureGrid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 18 };
        captureGrid.Children.Add(_thumbBox);
        var capText = Kit.V(10,
            Kit.Txt("Latest capture", "title"),
            _capNote,
            Kit.H(8,
                Kit.Btn("Test camera", IconData.Camera, "small", TestCamera),
                Kit.Btn("Open captures", IconData.Folder, "ghost small", () => Ctx.Host.OpenFolder(Ctx.Host.CapturesDir))));
        Grid.SetColumn(capText, 1);
        captureGrid.Children.Add(capText);
        captureGrid.Margin = new Thickness(0, 12);

        _urlSave.Tick += (_, _) =>
        {
            _urlSave.Stop();
            string url = (_url.Text ?? "").Trim();
            Save(g => g.AlertUrl = url);
        };
        _url.TextChanged += (_, _) =>
        {
            if (_syncing || !Kit.UserDriven(_url))
                return;
            _urlSave.Stop();
            _urlSave.Start();
        };

        var notifications = Kit.Section("Notifications", IconData.Bell, null,
            Kit.Row("Notify on lock, unlock & pause", "A small CryptoKey notification on every transition.", _notify),
            Kit.Row("Sound cues", "Synthesized lock/unlock tones and a tamper alarm.", _sounds));

        var evidence = Kit.Section("Tamper evidence", IconData.Camera,
            "Snapshots are sealed to your user account — unreadable if copied off this machine.",
            Kit.Gate(Kit.Row("Webcam snapshot on tamper events",
                "Privacy opt-in: fires on failed unlocks, clone suspicion and lock-defense trips.", _webcam),
                caps.Webcam, caps.Unavailable),
            caps.Webcam ? captureGrid : null);

        var remote = Kit.Section("Remote alerts", IconData.Webhook,
            "Security events POST to any webhook — an ntfy.sh topic pings your phone.",
            Kit.Row("Alert URL", null, _url),
            Kit.Row("Test the endpoint", "Sends the URL in the field, not the saved one — a bad URL should fail now, not during an attack.",
                Kit.Btn("Send test", IconData.Zap, "small", SendTest)));

        Content = Kit.PageScroll(Kit.V(16,
            Kit.PageHeader("Alerts & Evidence", "How CryptoKey tells you something happened."),
            notifications, evidence, remote));
    }

    private void Set(Action<GuardSettings> mutate)
    {
        if (!_syncing)
            Save(mutate);
    }

    public override void Refresh()
    {
        GuardSettings g = G;
        _syncing = true;
        try
        {
            _notify.IsChecked = g.BalloonTips;
            _sounds.IsChecked = g.Sounds;
            _webcam.IsChecked = g.WebcamOnTamper;
            if (!_urlSave.IsEnabled && !_url.IsFocused)
                _url.Text = g.AlertUrl;
        }
        finally
        {
            _syncing = false;
        }
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        RefreshCapture();
    }

    private async void RefreshCapture()
    {
        if (!Ctx.Caps.Webcam)
            return;
        bool on = G.WebcamOnTamper;
        CaptureInfo info = await Task.Run(() => Ctx.Host.LatestCapture(on));
        _capNote.Text = info.Note;
        Bitmap? old = _thumb.Source as Bitmap;
        _thumb.Source = null;
        if (info.Image != null)
        {
            try { _thumb.Source = new Bitmap(new MemoryStream(info.Image)); }
            catch (Exception) { }
        }
        old?.Dispose();
    }

    private void TestCamera()
    {
        Ctx.Host.TestCamera(Client.Log);
        Ctx.Toast("Snapshot requested — it lands in the captures folder.", false);
        // The snap warms the sensor for a second or two — refresh late.
        DispatcherTimer.RunOnce(RefreshCapture, TimeSpan.FromSeconds(4));
    }

    private void SendTest()
    {
        string url = (_url.Text ?? "").Trim();
        if (url.Length == 0)
        {
            Ctx.Toast("Set an alert URL first.", true);
            return;
        }
        AlertService.Send(url, "Test", "test alert — CryptoKey is armed", Client.Log);
        Ctx.Toast("Test alert queued — check your endpoint (failures log to guard.log).", false);
    }

    protected override void OnHidden()
    {
        if (_urlSave.IsEnabled)
        {
            _urlSave.Stop();
            string url = (_url.Text ?? "").Trim();
            Save(g => g.AlertUrl = url);
        }
    }
}
