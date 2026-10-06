using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// The setup wizard — first run and in-app re-enroll. A guided version of
/// `cryptokey enroll` driven by the same <see cref="EnrollmentFlow"/>:
/// plug in → see the phrase once → retype it → pick a policy → done. The
/// key art plays along: it seats itself the moment you pick your drive.
/// </summary>
internal sealed class OnboardingWindow : Window
{
    private enum Step { Welcome, Drive, Phrase, Confirm, Policy, Extras, Done }

    private readonly EnrollmentFlow _flow = new();
    private readonly IUiHost _host;
    private readonly bool _firstRun;
    private readonly Func<EnrollmentFlow, Action<GuardSettings>, Task<EnrollResult>> _commit;
    private readonly KeyVisual _key = new() { Height = 130 };
    private readonly TextBlock _title = Kit.Txt("", "h1");
    private readonly TextBlock _subtitle = Kit.Txt("", "body", "dim");
    private readonly ContentControl _body = new();
    private readonly Button _back;
    private readonly Button _next;
    private readonly StackPanel _dots = new() { Orientation = Orientation.Horizontal, Spacing = 6, HorizontalAlignment = HorizontalAlignment.Center };
    private readonly TextBlock _error = Kit.Txt("", "caption", "danger");
    private readonly DispatcherTimer _scan;

    private Step _step = Step.Welcome;
    private List<UsbDisk> _disks = new();
    private UsbDisk? _picked;
    private readonly StackPanel _driveList = new() { Spacing = 8 };
    private readonly CheckBox _wrote = new() { Content = "I've written it down — on paper, not on this computer" };
    private readonly TextBox _retype = new() { Watermark = "Type the phrase exactly as shown", Classes = { "phrase" } };
    private readonly Segmented _policy = new(ProtectionPresenter.Policies.Select(p => p.Label).ToArray());
    private readonly TextBlock _policyHelp = Kit.Txt("", "caption", "dim");
    private readonly Banner _policyWarn = new();
    private readonly ToggleSwitch _startup = new() { IsChecked = true };
    private readonly ToggleSwitch _admin = new() { IsChecked = false };
    private bool _scanning;

    /// <summary>True once the key is enrolled (config + keyfile written).</summary>
    public bool Enrolled { get; private set; }

    public OnboardingWindow(IUiHost host, bool firstRun,
        Func<EnrollmentFlow, Action<GuardSettings>, Task<EnrollResult>> commit)
    {
        _host = host;
        _firstRun = firstRun;
        _commit = commit;
        Title = firstRun ? "Set up CryptoKey" : "Re-enroll your key";
        Width = 720;
        Height = 660;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ExtendClientAreaToDecorationsHint = true;
        ExtendClientAreaTitleBarHeightHint = 36;
        try { Icon = new WindowIcon(host.AppIcon()); }
        catch (Exception) { }

        _back = Kit.Btn("Back", IconData.ArrowLeft, "ghost", Back);
        _next = Kit.Btn("Get started", IconData.ArrowRight, "primary", Next);
        _next.MinWidth = 150;

        _policy.SelectedIndex = Math.Max(0, Array.FindIndex(ProtectionPresenter.Policies,
            p => p.Policy == (_flow.Existing?.Guard.UnlockPolicy ?? UnlockPolicy.KeyOrPassphrase)));
        _policy.SelectionChanged += _ => UpdatePolicyCopy();
        _wrote.IsCheckedChanged += (_, _) => UpdateNav();
        _retype.TextChanged += (_, _) => { _retype.Classes.Remove("error"); _error.Text = ""; UpdateNav(); };
        _retype.KeyDown += (_, e) => { if (e.Key == Key.Enter && _next.IsEnabled) Next(); };
        _startup.IsCheckedChanged += (_, _) => _admin.IsEnabled = _startup.IsChecked == true;

        var footer = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto") };
        footer.Children.Add(_back);
        Grid.SetColumn(_dots, 1);
        _dots.VerticalAlignment = VerticalAlignment.Center;
        footer.Children.Add(_dots);
        Grid.SetColumn(_next, 2);
        footer.Children.Add(_next);

        _title.TextAlignment = TextAlignment.Center;
        _subtitle.TextAlignment = TextAlignment.Center;
        _subtitle.MaxWidth = 520;
        _subtitle.HorizontalAlignment = HorizontalAlignment.Center;

        var layout = new DockPanel { Margin = new Thickness(40, 44, 40, 28) };
        DockPanel.SetDock(footer, Dock.Bottom);
        layout.Children.Add(footer);
        var head = Kit.V(14, _key, _title, _subtitle);
        DockPanel.SetDock(head, Dock.Top);
        layout.Children.Add(head);
        DockPanel.SetDock(_error, Dock.Bottom);
        _error.Margin = new Thickness(0, 0, 0, 10);
        _error.TextAlignment = TextAlignment.Center;
        layout.Children.Add(_error);
        _body.Margin = new Thickness(0, 22, 0, 16);
        layout.Children.Add(new ScrollViewer { Content = _body });

        Content = new Grid { Children = { new GridTexture(), layout } };

        _scan = Kit.Timer(TimeSpan.FromSeconds(2), DispatcherPriority.Background, ScanDrives);
        Show(Step.Welcome);
    }

    private void Show(Step step)
    {
        _step = step;
        _error.Text = "";
        _scan.Stop();
        switch (step)
        {
            case Step.Welcome:
                _key.State = KeyVisualState.Absent;
                _title.Text = _firstRun ? "Your USB drive becomes your key" : "Enroll a new key";
                _subtitle.Text = _firstRun
                    ? "Pull it out and this computer locks. Plug it back in and you're in. Setup takes about a minute."
                    : _flow.Existing != null
                        ? $"This replaces the key currently enrolled (serial {_flow.Existing.DeviceSerial}). Your settings carry over."
                        : "Register a drive as your key.";
                _body.Content = Kit.V(10,
                    Feature(IconData.Usb, "Any USB drive works", "A small keyfile is written to it — your files are untouched."),
                    Feature(IconData.FileKey, "A recovery phrase for emergencies", "Shown once, stored only as a hash."),
                    Feature(IconData.Shield, "Honest about its limits", "A strong deterrent that pairs with your OS password and disk encryption."));
                break;

            case Step.Drive:
                _key.State = _picked != null ? KeyVisualState.Armed : KeyVisualState.Locked;
                _title.Text = "Plug in the drive you'll use";
                _subtitle.Text = "Pick it from the list — it appears here as soon as it's connected.";
                _body.Content = _driveList;
                ScanDrives();
                _scan.Start();
                break;

            case Step.Phrase:
                _key.State = KeyVisualState.Verifying;
                _title.Text = "Your recovery phrase";
                _subtitle.Text = "The failsafe if your key is lost or broken. It's shown this one time only.";
                _wrote.IsChecked = false;
                var phrase = new TextBlock
                {
                    Text = _flow.Phrase,
                    FontFamily = Palette.Mono,
                    FontSize = 30,
                    FontWeight = FontWeight.Bold,
                    LetterSpacing = 2,
                    Foreground = Palette.Armed,
                    TextAlignment = TextAlignment.Center,
                    TextWrapping = TextWrapping.Wrap,
                };
                _body.Content = Kit.V(16,
                    new Border
                    {
                        Background = Palette.CarbonDeep,
                        BorderBrush = Palette.Brush(DesignTokens.Armed, 0x55),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(14),
                        Padding = new Thickness(20, 26),
                        Child = phrase,
                    },
                    _wrote);
                break;

            case Step.Confirm:
                _key.State = KeyVisualState.Verifying;
                _title.Text = "Type it back";
                _subtitle.Text = "Case, spaces and dashes don't matter. O/0 and I/L/1 are treated the same.";
                _retype.Text = "";
                _body.Content = Kit.V(10, _retype,
                    Kit.Txt($"{EnrollmentFlow.MaxConfirmAttempts - _flow.ConfirmAttempts} attempts left", "caption", "faint"));
                Dispatcher.UIThread.Post(() => _retype.Focus());
                break;

            case Step.Policy:
                _key.State = KeyVisualState.Armed;
                _title.Text = "What should unlock this computer?";
                _subtitle.Text = "You can change this any time under Protection.";
                UpdatePolicyCopy();
                _body.Content = Kit.V(12, _policy, _policyHelp, _policyWarn);
                break;

            case Step.Extras:
                _key.State = KeyVisualState.Armed;
                _title.Text = "Start with your session";
                _subtitle.Text = "Recommended — a lock that isn't running can't protect you.";
                _admin.IsEnabled = _startup.IsChecked == true;
                _body.Content = new Border
                {
                    Classes = { "card" },
                    Child = Kit.V(0,
                        Kit.Row("Start at login", "The guard starts automatically when you sign in.", _startup),
                        Kit.Divider(),
                        _host.Capabilities.Elevation
                            ? Kit.Row("As administrator", "Stronger lock — asks for administrator approval once.", _admin)
                            : null),
                };
                break;

            case Step.Done:
                _key.State = KeyVisualState.Armed;
                _title.Text = "You're protected";
                _subtitle.Text = "Try it: pull the key out. The screen locks instantly — plug it back in to unlock.";
                _body.Content = Kit.V(10,
                    Feature(IconData.CircleCheck, "Key enrolled", _picked?.Model ?? "USB drive"),
                    Feature(IconData.FileKey, "Recovery phrase saved", "Keep the paper copy somewhere safe."),
                    Feature(IconData.Bell, "CryptoKey lives in your tray", "Click the tray icon any time for quick controls."));
                break;
        }
        RenderDots();
        UpdateNav();
    }

    private static Control Feature(string icon, string title, string text)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 14 };
        g.Children.Add(new Border
        {
            Width = 36, Height = 36, CornerRadius = new CornerRadius(10),
            Background = Palette.Brush(DesignTokens.Signal, 0x1E),
            Child = new Icon(icon, 18) { Foreground = Palette.Signal,
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
        });
        var t = Kit.V(2, Kit.Txt(title, "title"), Kit.Txt(text, "caption", "dim"));
        t.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(t, 1);
        g.Children.Add(t);
        return new Border { Classes = { "card" }, Padding = new Thickness(16, 12), Child = g };
    }

    private void RenderDots()
    {
        _dots.Children.Clear();
        int count = (int)Step.Done + 1;
        for (int i = 0; i < count; i++)
        {
            bool skipped = i == (int)Step.Extras && !_firstRun;
            if (skipped)
                continue;
            _dots.Children.Add(new Border
            {
                Width = i == (int)_step ? 22 : 7,
                Height = 7,
                CornerRadius = new CornerRadius(4),
                Background = i <= (int)_step ? Palette.Signal : Palette.Raised,
            });
        }
    }

    private void UpdateNav()
    {
        _back.IsVisible = _step is Step.Drive or Step.Policy or Step.Extras;
        (string text, bool enabled) = _step switch
        {
            Step.Welcome => ("Get started", true),
            Step.Drive => ("Use this drive", _picked != null),
            Step.Phrase => ("I've written it down", _wrote.IsChecked == true),
            Step.Confirm => ("Confirm", (_retype.Text?.Length ?? 0) > 0),
            Step.Policy => (_firstRun ? "Continue" : "Enroll key", true),
            Step.Extras => ("Finish setup", true),
            _ => ("Done", true),
        };
        Kit.SetLabel(_next, text, _step == Step.Done ? IconData.Check : IconData.ArrowRight);
        _next.IsEnabled = enabled;
    }

    private void UpdatePolicyCopy()
    {
        int i = Math.Max(0, _policy.SelectedIndex);
        _policyHelp.Text = ProtectionPresenter.Policies[i].Help;
        var w = ProtectionPresenter.Warnings(ProtectionPresenter.Policies[i].Policy, privateDesktop: false);
        _policyWarn.IsVisible = w.Count > 0;
        _policyWarn.Set(string.Join("\n", w), Tone.Warn);
    }

    private async void ScanDrives()
    {
        if (_scanning)
            return;
        _scanning = true;
        try
        {
            List<UsbDisk> disks;
            try { disks = await Task.Run(EnrollmentFlow.ListDisks); }
            catch (Exception ex)
            {
                _error.Text = $"Couldn't list USB drives: {ex.Message}";
                return;
            }
            if (_step != Step.Drive)
                return;
            if (disks.Select(d => d.DeviceId + d.SerialNumber).SequenceEqual(_disks.Select(d => d.DeviceId + d.SerialNumber)))
                return;
            _disks = disks;
            if (_picked != null && !disks.Any(d => d.DeviceId == _picked.DeviceId))
                _picked = null;
            RenderDrives();
        }
        finally
        {
            _scanning = false;
        }
    }

    private void RenderDrives()
    {
        _driveList.Children.Clear();
        if (_disks.Count == 0)
        {
            _driveList.Children.Add(new Border
            {
                Classes = { "well" },
                Child = Kit.H(12, new Icon(IconData.Plug, 20) { Foreground = Palette.TextFaint },
                    Kit.Txt("Waiting for a USB drive… plug one in.", "body", "dim")),
            });
        }
        foreach (UsbDisk d in _disks)
        {
            bool sel = _picked?.DeviceId == d.DeviceId;
            string vols = d.VolumePaths.Count > 0 ? string.Join(", ", d.VolumePaths) : "no volume";
            string serial = string.IsNullOrEmpty(d.SerialNumber) ? "blank serial" : d.SerialNumber;
            var card = new Button
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Padding = new Thickness(16, 12),
                Background = sel ? Palette.Brush(DesignTokens.Signal, 0x1C) : Palette.Surface,
                BorderBrush = sel ? Palette.Signal : Palette.Hairline,
                CornerRadius = new CornerRadius(12),
                Content = new Grid
                {
                    ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"),
                    ColumnSpacing = 14,
                    Children =
                    {
                        new Icon(IconData.Usb, 22) { Foreground = sel ? Palette.Signal : Palette.TextDim },
                        WithCol(Kit.V(2, Kit.Txt(d.Model, "title"),
                            Kit.Txt($"{vols} · {serial}", "mono", "dim")), 1),
                        WithCol(sel ? new Icon(IconData.CircleCheck, 20) { Foreground = Palette.Signal } : new Border(), 2),
                    },
                },
            };
            UsbDisk captured = d;
            card.Click += (_, _) => Pick(captured);
            _driveList.Children.Add(card);
        }
        UpdateNav();
    }

    private static Control WithCol(Control c, int col)
    {
        Grid.SetColumn(c, col);
        c.VerticalAlignment = VerticalAlignment.Center;
        return c;
    }

    private void Pick(UsbDisk d)
    {
        if (d.VolumePaths.Count == 0)
        {
            _error.Text = "That drive has no mounted volume — format it or pick another.";
            return;
        }
        _picked = d;
        _error.Text = string.IsNullOrEmpty(d.SerialNumber)
            ? "Heads up: this drive reports a blank serial number — matching may be unreliable."
            : "";
        _key.State = KeyVisualState.Armed; // the key seats itself
        RenderDrives();
    }

    private void Back()
    {
        switch (_step)
        {
            case Step.Drive: Show(Step.Welcome); break;
            case Step.Policy: Show(Step.Drive); break; // a new pick generates a fresh phrase
            case Step.Extras: Show(Step.Policy); break;
        }
    }

    private async void Next()
    {
        switch (_step)
        {
            case Step.Welcome:
                Show(Step.Drive);
                break;
            case Step.Drive when _picked != null:
                if (_flow.SelectDisk(_picked) is string err)
                {
                    _error.Text = err;
                    return;
                }
                Show(Step.Phrase);
                break;
            case Step.Phrase:
                Show(Step.Confirm);
                break;
            case Step.Confirm:
                switch (_flow.Confirm((_retype.Text ?? "").AsSpan()))
                {
                    case ConfirmResult.Match:
                        _retype.Text = "";
                        Show(Step.Policy);
                        break;
                    case ConfirmResult.Mismatch:
                        _retype.Classes.Add("error");
                        Show(Step.Confirm);
                        _error.Text = "That doesn't match — check each group and try again.";
                        break;
                    default:
                        // Out of tries — a fresh pick generates a fresh phrase.
                        _picked = null;
                        Show(Step.Drive);
                        _error.Text = "Too many mismatches — pick your drive again for a new phrase.";
                        break;
                }
                break;
            case Step.Policy:
                if (_firstRun)
                    Show(Step.Extras);
                else
                    await CommitAsync();
                break;
            case Step.Extras:
                await CommitAsync();
                break;
            case Step.Done:
                Close();
                break;
        }
    }

    private async Task CommitAsync()
    {
        UnlockPolicy policy = ProtectionPresenter.Policies[Math.Max(0, _policy.SelectedIndex)].Policy;
        _next.IsEnabled = false;
        _back.IsEnabled = false;
        Kit.SetLabel(_next, "Writing keyfile…", IconData.Usb);
        EnrollResult result;
        try
        {
            result = await _commit(_flow, g => g.UnlockPolicy = policy);
        }
        catch (Exception ex)
        {
            result = new EnrollResult(false, ex.Message, null, null, Array.Empty<string>());
        }
        _back.IsEnabled = true;
        if (!result.Ok)
        {
            _error.Text = result.Message;
            UpdateNav();
            return;
        }
        Enrolled = true;
        string? startupError = null;
        if (_firstRun && _host.Capabilities.StartupAtLogin && _startup.IsChecked == true)
        {
            UiStartupMode mode = _admin.IsChecked == true && _host.Capabilities.Elevation
                ? UiStartupMode.Elevated : UiStartupMode.Normal;
            string? err = await _host.SetStartupModeAsync(mode, _ => { });
            if (err != null)
                startupError = $"Enrolled — but login startup wasn't set: {err}";
        }
        Show(Step.Done);
        if (startupError != null)
            _error.Text = startupError;
        foreach (string w in result.Warnings)
            _error.Text = (string.IsNullOrEmpty(_error.Text) ? "" : _error.Text + "\n") + w;
    }

    protected override void OnClosed(EventArgs e)
    {
        _scan.Stop();
        _retype.Text = "";
        base.OnClosed(e);
    }
}
