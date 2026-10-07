using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// Home: the key itself as the hero (state you can read across the room),
/// one-tap actions, the enrolled key, the vault at a glance, and the latest
/// activity.
/// </summary>
internal sealed class HomePage : Page
{
    private readonly KeyVisual _key = new() { Height = 210, MinWidth = 300 };
    private readonly TextBlock _word = Kit.Txt("ARMED", "hero");
    private readonly TextBlock _reason = Kit.Txt("", "body", "dim");
    private readonly WrapPanel _chips = new() { Orientation = Orientation.Horizontal };
    private readonly Button _lock;
    private readonly Button _pause;
    private readonly Button _resume;
    private readonly Border _hero;

    private readonly TextBlock _keyEyebrow = Kit.Txt("ENROLLED KEY", "eyebrow");
    private readonly TextBlock _keyTitle = Kit.Txt("", "h2");
    private readonly TextBlock _keySerial = Kit.Txt("", "mono", "dim");
    private readonly TextBlock _keyDetail = Kit.Txt("", "caption", "dim");
    private readonly Button _setupKey;

    private readonly StatusChip _vaultChip = new();
    private readonly TextBlock _vaultLine = Kit.Txt("", "caption", "dim");
    private readonly Button _vaultAction;

    private readonly StackPanel _feed = new() { Spacing = 0 };
    private readonly DispatcherTimer _pauseTick;
    private DateTime? _pauseUntilSeen;
    private DateTime _pauseStart;

    public HomePage(PageContext ctx) : base(ctx)
    {
        _lock = Kit.Btn("Lock now", IconData.Lock, "lock", () => Client.Lock());
        _resume = Kit.Btn("Resume", IconData.Play, "primary", () => Client.Resume());
        _pause = Kit.Btn("Pause", IconData.Pause, "");
        var menu = new MenuFlyout();
        foreach (int mins in new[] { 5, 15, 60 })
        {
            var item = new MenuItem { Header = $"Pause for {mins} minutes" };
            item.Click += async (_, _) =>
            {
                string? err = await Client.Pause(mins);
                Report(err, $"Auto-lock paused for {mins} minutes");
            };
            menu.Items.Add(item);
        }
        _pause.Flyout = menu;
        _chips.Children.Clear();

        // ---- Hero ----
        var stateCol = Kit.V(10,
            Kit.Txt("GUARD STATUS", "eyebrow"),
            _word,
            _reason,
            _chips,
            Kit.H(10, _lock, _pause, _resume));
        _chips.Margin = new Thickness(0, 4, 0, 6);
        _reason.MaxWidth = 440;
        stateCol.VerticalAlignment = VerticalAlignment.Center;

        var heroGrid = new Grid { ColumnDefinitions = new ColumnDefinitions("1.1*,*"), ColumnSpacing = 24 };
        heroGrid.Children.Add(_key);
        Grid.SetColumn(stateCol, 1);
        heroGrid.Children.Add(stateCol);
        _hero = new Border
        {
            Classes = { "card" },
            Padding = new Thickness(24, 28),
            Child = heroGrid,
        };

        // ---- Key card ----
        _setupKey = Kit.Btn("Set up a key", IconData.Usb, "primary small",
            () => Ctx.OpenOnboarding());
        _setupKey.HorizontalAlignment = HorizontalAlignment.Left;
        _setupKey.IsVisible = false;
        var keyCard = new Border
        {
            Classes = { "card" },
            Child = Kit.V(8,
                Kit.H(8, new Icon(IconData.Usb, 16) { Foreground = Palette.Signal }, _keyEyebrow),
                _keyTitle, _keySerial, _keyDetail,
                _setupKey,
                LinkButton("Manage key & recovery", () => Ctx.Navigate(Route.Key))),
        };

        // ---- Vault card ----
        _vaultAction = Kit.Btn("Open vault page", IconData.ArrowRight, "small", () => Ctx.Navigate(Route.Vault));
        var vaultCard = new Border
        {
            Classes = { "card" },
            Child = Kit.V(8,
                Kit.H(8, new Icon(IconData.Vault, 16) { Foreground = Palette.Signal }, Kit.Txt("ENCRYPTED VAULT", "eyebrow")),
                _vaultChip, _vaultLine,
                Kit.H(8, _vaultAction, LinkButton("Vault settings", () => Ctx.Navigate(Route.Vault)))),
        };
        _vaultChip.HorizontalAlignment = HorizontalAlignment.Left;

        var mid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,*"), ColumnSpacing = 16 };
        mid.Children.Add(keyCard);
        Grid.SetColumn(vaultCard, 1);
        mid.Children.Add(vaultCard);

        // ---- Activity preview ----
        var feedHeader = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        feedHeader.Children.Add(Kit.H(8, new Icon(IconData.Activity, 16) { Foreground = Palette.Signal },
            Kit.Txt("RECENT ACTIVITY", "eyebrow")));
        var all = LinkButton("View all", () => Ctx.Navigate(Route.Activity));
        Grid.SetColumn(all, 1);
        feedHeader.Children.Add(all);
        var feedCard = new Border { Classes = { "card" }, Child = Kit.V(10, feedHeader, _feed) };

        Content = Kit.PageScroll(Kit.V(16, _hero, mid, feedCard));

        _pauseTick = Kit.Timer(TimeSpan.FromSeconds(1), DispatcherPriority.Background, UpdatePause);
    }

    private static Button LinkButton(string text, Action onClick)
    {
        var b = Kit.Btn(text, IconData.ChevronRight, "ghost small", onClick);
        b.Padding = new Thickness(6, 2);
        b.HorizontalAlignment = HorizontalAlignment.Left;
        b.Foreground = Palette.Signal;
        return b;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        Client.ActivityLogged += OnActivity;
        RebuildFeed();
    }

    protected override void OnHidden()
    {
        Client.ActivityLogged -= OnActivity;
        _pauseTick.Stop();
    }

    private void OnActivity(string _) => RebuildFeed();

    private void RebuildFeed()
    {
        _feed.Children.Clear();
        var items = Client.Activity.TakeLast(6).Reverse().Select(ActivityPresenter.Parse).ToList();
        if (items.Count == 0)
            _feed.Children.Add(Kit.Txt("Nothing yet — activity appears here as it happens.", "caption", "dim"));
        foreach (ActivityItem it in items)
            _feed.Children.Add(FeedRow(it));
    }

    internal static Control FeedRow(ActivityItem it)
    {
        var grid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("Auto,Auto,*"),
            ColumnSpacing = 12,
            Margin = new Thickness(0, 6),
        };
        var time = Kit.Txt(it.Time, "mono", "faint");
        time.FontSize = 11.5;
        time.Width = 64;
        time.VerticalAlignment = VerticalAlignment.Top;
        grid.Children.Add(time);
        var dot = new Ellipse
        {
            Width = 7, Height = 7,
            Fill = Kit.ToneBrush(it.Tone),
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 5, 0, 0),
        };
        Grid.SetColumn(dot, 1);
        grid.Children.Add(dot);
        var msg = Kit.Txt(it.Message, "caption");
        msg.FontSize = 12.5;
        msg.Foreground = it.Tone == Tone.Danger ? Palette.Locked : Palette.Text;
        Grid.SetColumn(msg, 2);
        grid.Children.Add(msg);
        return grid;
    }

    public override void Refresh()
    {
        StatusSnapshot s = Client.Snapshot;
        HomeView v = HomePresenter.Present(s, Client.Settings, Client.DevMode, Ctx.Host.IsElevated);

        _key.State = v.Visual;
        _word.Text = v.StateWord;
        _word.Foreground = Kit.ToneBrush(v.Accent);
        _reason.Text = v.Reason;
        _chips.Children.Clear();
        foreach (Chip c in v.Chips)
            _chips.Children.Add(new StatusChip(c) { Margin = new Thickness(0, 0, 6, 6) });
        _lock.IsEnabled = v.CanLock;
        _pause.IsEnabled = v.CanPause;
        _resume.IsVisible = v.CanResume;
        _pause.IsVisible = true;

        uint accent = Kit.ToneArgb(v.Accent);
        _hero.Background = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Palette.C(accent, 0x1C), 0),
                new GradientStop(Palette.C(DesignTokens.Surface), 0.55),
            },
        };
        _hero.BorderBrush = Palette.Brush(accent, 0x40);

        _keyEyebrow.Text = s.Enrolled ? "ENROLLED KEY" : "KEY";
        _setupKey.IsVisible = !s.Enrolled && s.State != GuardState.Locked;
        _keyTitle.Text = v.KeyTitle;
        _keySerial.Text = v.KeySerial;
        _keyDetail.Text = v.KeyDetail;

        if (s.Vault is VaultStatus vs)
        {
            Chip chip = HomePresenter.VaultChip(vs);
            _vaultChip.Set(chip.Text, chip.Tone);
            _vaultLine.Text = vs.State switch
            {
                VaultState.Mounted => $"Your encrypted drive is open at {vs.MountPoint}.",
                VaultState.Unsealed => "Unlocked in memory — mount it to use the drive.",
                VaultState.Sealed => "Sealed until your key verifies.",
                _ => "Needs attention — see the Vault page.",
            };
            if (vs.State == VaultState.Mounted)
                Kit.SetLabel(_vaultAction, $"Open {vs.MountPoint}", IconData.Folder);
            else if (vs.State == VaultState.Unsealed)
                Kit.SetLabel(_vaultAction, "Mount", IconData.Play);
            else
                Kit.SetLabel(_vaultAction, "Open vault page", IconData.ArrowRight);
            _vaultAction.Tag = vs.State;
        }
        else
        {
            _vaultChip.Set(Ctx.Caps.Vault ? "no vault" : "unavailable", Tone.Neutral);
            _vaultLine.Text = Ctx.Caps.Vault
                ? "An encrypted drive that only exists while your key is in."
                : Ctx.Caps.Unavailable;
            Kit.SetLabel(_vaultAction, "Set up a vault", IconData.ArrowRight);
            _vaultAction.Tag = null;
            _vaultAction.IsEnabled = Ctx.Caps.Vault;
        }
        _vaultAction.Click -= OnVaultAction;
        _vaultAction.Click += OnVaultAction;

        UpdatePause();
        if (s.State == GuardState.Paused)
            _pauseTick.Start();
        else
            _pauseTick.Stop();
    }

    private async void OnVaultAction(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        e.Handled = true;
        switch (_vaultAction.Tag)
        {
            case VaultState.Mounted when Client.Snapshot.Vault is VaultStatus vs:
                Ctx.Host.OpenFolder(vs.MountPoint + System.IO.Path.DirectorySeparatorChar);
                break;
            case VaultState.Unsealed:
                await MountVault();
                break;
            default:
                Ctx.Navigate(Route.Vault);
                break;
        }
    }

    /// <summary>Through the dispatch table like every mutator — the account
    /// gate lives there; a dead session gets the sign-in face, then retries.</summary>
    private async Task MountVault()
    {
        string reply = await Client.Dispatch("vault mount");
        if (RetryAfterAuth(reply, () => _ = MountVault()))
            return;
        Report(ReplyError(reply));
    }

    private void UpdatePause()
    {
        StatusSnapshot s = Client.Snapshot;
        if (s.State != GuardState.Paused || s.PausedUntil is not DateTime until)
        {
            _pauseUntilSeen = null;
            return;
        }
        if (_pauseUntilSeen != until)
        {
            _pauseUntilSeen = until;
            _pauseStart = DateTime.Now;
        }
        _key.PauseProgress = HomePresenter.PauseProgress(until, DateTime.Now, until - _pauseStart);
        int mins = (int)Math.Ceiling((until - DateTime.Now).TotalMinutes);
        _reason.Text = $"Auto-lock resumes at {until:HH:mm} — about {Math.Max(mins, 0)} min left.";
    }
}
