using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>Which face the auth window is showing.</summary>
internal enum AuthMode
{
    /// <summary>First run with no account — email + password + confirm.</summary>
    Create,
    /// <summary>Returning install — email + password (+ forgot / offline grace).</summary>
    SignIn,
    /// <summary>Send the recovery email.</summary>
    Forgot,
    /// <summary>cryptokey:// deep link landed — set a new password (key required).</summary>
    Reset,
    /// <summary>Account section missing/corrupt — online sign-in rewrites it.</summary>
    Relink,
}

/// <summary>
/// The account gate: same chrome as the onboarding wizard (grid texture,
/// animated key visual, centered card, footer button). Drives
/// <see cref="AuthService.Current"/> directly — the record/session it
/// establishes authorizes dashboard + gated ops for the rest of the run.
///
/// This is an APPLICATION gate: the USB key and recovery phrase still
/// lock the workstation, and the guard runs whether or not anyone signs
/// in here. Closing without authenticating leaves the guard armed and
/// the dashboard closed.
/// </summary>
internal sealed class AuthWindow : Window
{
    private readonly IUiHost _host;
    private readonly AuthService _auth;
    private readonly Func<bool>? _keyPresent;
    private string? _tokenHash;

    private readonly KeyVisual _key = new() { Height = 110 };
    private readonly TextBlock _title = Kit.Txt("", "h1");
    private readonly TextBlock _subtitle = Kit.Txt("", "body", "dim");
    private readonly ContentControl _body = new();
    private readonly Border _card = new() { Classes = { "card" } };
    private readonly Button _back;
    private readonly Button _next;
    private readonly Banner _errorBanner = new() { IsVisible = false };
    private readonly Banner _banner = new() { IsVisible = false };
    private readonly StackPanel _switchRow;
    private readonly TextBlock _switchCaption = Kit.Txt("", "caption", "dim");
    private readonly StatusChip _keyChip = new() { HorizontalAlignment = HorizontalAlignment.Center };
    private readonly Border _keyChipRow;
    private readonly DispatcherTimer _keyTimer;

    private readonly TextBox _email = new()
    {
        Watermark = "you@example.com",
        Classes = { "field" },
    };
    private readonly TextBox _password = new()
    {
        Watermark = "Password",
        PasswordChar = '●',
        Classes = { "field" },
    };
    private readonly TextBox _confirm = new()
    {
        Watermark = "Repeat the password",
        PasswordChar = '●',
        Classes = { "field" },
    };
    private readonly Icon _confirmCheck = new(IconData.CircleCheck, 15)
    {
        Foreground = Palette.Armed,
        IsVisible = false,
        VerticalAlignment = VerticalAlignment.Center,
    };
    private readonly StrengthMeter _meter = new();
    private readonly TextBlock _strength = Kit.Txt("", "caption", "dim");
    private readonly TextBlock _match = Kit.Txt("", "caption", "dim");
    private readonly Button _pwEye;
    private readonly Button _confirmEye;

    // Face wrappers are built once: a control has exactly one logical
    // parent, so every shared leaf (fields, meter, chip) needs a stable
    // home — per-mode contents then swap by clearing/re-adding the card's
    // top-level children rather than re-parenting the leaves themselves.
    private readonly ContentControl _pwLabelSlot = new();
    private readonly Control _emailField;
    private readonly Control _passwordField;
    private readonly Control _confirmField;
    private readonly Control _strengthRow;

    private AuthMode _mode;
    private string _nextText = "Continue";
    private string? _nextIcon = IconData.ArrowRight;

    /// <summary>True when the window closed having authorized the session.</summary>
    public bool Authenticated { get; private set; }

    /// <param name="keyPresent">Reset/Relink need the enrolled key to
    /// re-attest the record write — the caller supplies the check.</param>
    public AuthWindow(IUiHost host, AuthMode mode, Func<bool>? keyPresent = null,
        string? tokenHash = null)
    {
        _host = host;
        _auth = AuthService.Current;
        _keyPresent = keyPresent;
        _tokenHash = tokenHash;
        _mode = mode;

        Title = "CryptoKey";
        Width = 520;
        Height = 620;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ExtendClientAreaToDecorationsHint = true;
        ExtendClientAreaTitleBarHeightHint = 36;
        try { Icon = new WindowIcon(host.AppIcon()); }
        catch (Exception) { }

        _back = Kit.Btn("Back", IconData.ArrowLeft, "ghost", () => Show(AuthMode.SignIn));
        _next = Kit.Btn("Continue", IconData.ArrowRight, "primary", () => _ = Submit());
        _next.MinWidth = 150;

        // Fields get leading icons; passwords get an eye toggle on the
        // right, and the confirm a match check beside its eye.
        _email.InnerLeftContent = LeadIcon(IconData.Mail);
        _password.InnerLeftContent = LeadIcon(IconData.Key);
        _confirm.InnerLeftContent = LeadIcon(IconData.Lock);
        _pwEye = Eye(_password);
        _confirmEye = Eye(_confirm);
        _password.InnerRightContent = _pwEye;
        _confirm.InnerRightContent = Kit.H(4, _confirmCheck, _confirmEye);

        _email.TextChanged += (_, _) => { ClearErrors(); UpdateNav(); };
        _password.TextChanged += (_, _) =>
        {
            ClearErrors();
            (int score, string text) = Strength(_password.Text ?? "");
            bool show = _mode is AuthMode.Create or AuthMode.Reset && score > 0;
            _meter.Score = show ? score : 0;
            _strength.Text = show ? text : "";
            UpdateMatch();
            UpdateNav();
        };
        _confirm.TextChanged += (_, _) =>
        {
            ClearErrors();
            UpdateMatch();
            UpdateNav();
        };
        _email.KeyDown += (_, e) =>
        { if (e.Key == Key.Enter) _password.Focus(); };
        _password.KeyDown += (_, e) =>
        { if (e.Key == Key.Enter && _next.IsEnabled) _ = Submit(); };
        _confirm.KeyDown += (_, e) =>
        { if (e.Key == Key.Enter && _next.IsEnabled) _ = Submit(); };

        _forgotLink = Kit.Btn("Forgot password", null, "ghost",
            () => Show(AuthMode.Forgot));
        _forgotLink.FontSize = 12;
        _forgotLink.MinHeight = 0;
        _forgotLink.Padding = new Thickness(6, 2);
        _switchLink = Kit.Btn("Create one", null, "ghost", () =>
            Show(_mode == AuthMode.SignIn ? AuthMode.Create : AuthMode.SignIn));
        _switchLink.FontSize = 12;
        _switchLink.MinHeight = 0;
        _switchLink.Padding = new Thickness(6, 2);
        _relinkLink = Kit.Btn("Relink a different account", null, "ghost",
            () => Show(AuthMode.Relink));
        _relinkLink.FontSize = 12;
        _relinkLink.MinHeight = 0;
        _relinkLink.Padding = new Thickness(6, 2);

        _switchRow = Kit.H(6, _switchCaption, _switchLink, _relinkLink);
        _switchRow.HorizontalAlignment = HorizontalAlignment.Center;

        _emailField = Field("EMAIL", _email);
        _passwordField = Field("PASSWORD", _password, _pwLabelSlot);
        _confirmField = Field("REPEAT PASSWORD", _confirm);
        _meter.VerticalAlignment = VerticalAlignment.Center;
        _strengthRow = Kit.H(10, _meter, _strength);
        _keyChipRow = new Border
        {
            Padding = new Thickness(0, 2),
            Child = _keyChip,
        };

        var footer = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto") };
        footer.Children.Add(_back);
        Grid.SetColumn(_next, 2);
        footer.Children.Add(_next);

        _title.TextAlignment = TextAlignment.Center;
        _subtitle.TextAlignment = TextAlignment.Center;
        _subtitle.MaxWidth = 400;
        _subtitle.TextWrapping = TextWrapping.Wrap;
        _subtitle.HorizontalAlignment = HorizontalAlignment.Center;
        var eyebrow = Kit.Txt("CRYPTOKEY ACCOUNT", "eyebrow");
        eyebrow.HorizontalAlignment = HorizontalAlignment.Center;
        var head = Kit.V(10, _key, eyebrow, _title, _subtitle, _banner);

        _body.Transitions = new Transitions
        {
            new DoubleTransition
            {
                Property = OpacityProperty,
                Duration = Motion.Duration(120),
            },
        };
        _body.Content = _card;
        var mid = new StackPanel
        {
            Spacing = 8,
            VerticalAlignment = VerticalAlignment.Center,
            Children = { _body, _errorBanner, _switchRow },
        };

        var layout = new Grid
        {
            RowDefinitions = new RowDefinitions("Auto,*,Auto"),
            Margin = new Thickness(36, 30, 36, 20),
        };
        layout.Children.Add(head);
        var scroll = new ScrollViewer { Content = mid };
        Grid.SetRow(scroll, 1);
        layout.Children.Add(scroll);
        Grid.SetRow(footer, 2);
        layout.Children.Add(footer);

        Content = new Grid { Children = { new GridTexture(), layout } };

        // The Reset/Relink fence is visible before submit — the chip
        // tracks the drive on a 1s beat while a key-required face is up.
        _keyTimer = Kit.Timer(TimeSpan.FromSeconds(1),
            DispatcherPriority.Background, UpdateKeyChip);
        Closed += (_, _) => _keyTimer.Stop();
        Show(mode);
    }

    private readonly Button _forgotLink;
    private readonly Button _switchLink;
    private readonly Button _relinkLink;

    private static Icon LeadIcon(string data) => new(data, 15)
    {
        Foreground = Palette.TextFaint,
        Margin = new Thickness(10, 0, 0, 0),
        VerticalAlignment = VerticalAlignment.Center,
    };

    /// <summary>Chromeless eye button that reveals/masks a password field.</summary>
    private static Button Eye(TextBox box)
    {
        var icon = new Icon(IconData.Eye, 15) { VerticalAlignment = VerticalAlignment.Center };
        var b = new Button
        {
            Classes = { "icon" },
            Content = icon,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 4, 0),
        };
        b.Click += (_, _) =>
        {
            bool hidden = box.PasswordChar == '●';
            box.PasswordChar = hidden ? '\0' : '●';
            icon.Data = hidden ? IconData.EyeOff : IconData.Eye;
        };
        Kit.AutomationName(b, "Show password");
        return b;
    }

    /// <summary>Eyebrow label row + field — the card's field idiom.</summary>
    private static Control Field(string label, TextBox box, Control? labelRight = null)
    {
        var lab = Kit.Txt(label, "eyebrow");
        lab.VerticalAlignment = VerticalAlignment.Center;
        var head = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        head.Children.Add(lab);
        if (labelRight != null)
        {
            Grid.SetColumn(labelRight, 1);
            labelRight.VerticalAlignment = VerticalAlignment.Center;
            head.Children.Add(labelRight);
        }
        return Kit.V(6, head, box);
    }

    private void UpdateMatch()
    {
        bool has = (_confirm.Text?.Length ?? 0) > 0;
        bool match = has && _password.Text == _confirm.Text;
        _match.Text = has ? (match ? "Match" : "Passwords don't match") : "";
        _confirmCheck.IsVisible = match;
    }

    private void UpdateKeyChip()
        => _keyChip.Set(_keyPresent?.Invoke() == true
                ? "USB key inserted" : "Insert your USB key to finish",
            _keyPresent?.Invoke() == true ? Tone.Ok : Tone.Warn);

    // ---------------------------------------------------------- modes

    /// <summary>Swap to a forced face after construction — a recovery deep
    /// link arriving while a face is already up lands here with its token.</summary>
    public void SwitchFace(AuthMode mode, string? tokenHash)
    {
        if (tokenHash != null)
            _tokenHash = tokenHash;
        _done = false;
        Show(mode);
    }

    private void Show(AuthMode mode)
    {
        _mode = mode;
        ClearErrors();
        _match.Text = "";
        _confirmCheck.IsVisible = false;
        _meter.Score = 0;
        _strength.Text = "";
        _key.State = KeyVisualState.Verifying;

        bool unconfigured = !_auth.Configured;
        _banner.IsVisible = unconfigured;
        if (unconfigured)
            _banner.Set("supabase.json is missing or invalid — online auth is off. " +
                "Offline unlock still works for a linked account.", Tone.Warn);

        bool keyFace = mode is AuthMode.Reset or AuthMode.Relink;
        if (keyFace)
        {
            UpdateKeyChip();
            _keyTimer.Start();
        }
        else
        {
            _keyTimer.Stop();
        }
        _pwLabelSlot.Content = mode == AuthMode.SignIn ? _forgotLink : null;

        // Release the previous face — clearing detaches every wrapper so a
        // leaf never sees two parents.
        (_card.Child as Panel)?.Children.Clear();

        switch (mode)
        {
            case AuthMode.Create:
                Title = "Create account — CryptoKey";
                _title.Text = "Create your CryptoKey account";
                _subtitle.Text = "One account per install — it gates this dashboard and " +
                    "sensitive commands. Your USB key stays the real lock.";
                _card.Child = Kit.V(12,
                    _emailField, _passwordField, _strengthRow, _confirmField, _match);
                SetNext("Create account", IconData.ArrowRight);
                break;

            case AuthMode.SignIn:
                Title = "Sign in — CryptoKey";
                _title.Text = "Sign in to CryptoKey";
                _subtitle.Text = _auth.State == AuthGateState.Locked
                    ? "The dashboard unlocks for this session after sign-in. " +
                      "Offline? The same password still works."
                    : "Sign in once — the dashboard and sensitive commands open " +
                      "for the rest of this session.";
                _email.Text = _auth.Record?.Email ?? _email.Text;
                _card.Child = Kit.V(12, _emailField, _passwordField);
                SetNext("Sign in", IconData.ArrowRight);
                break;

            case AuthMode.Forgot:
                Title = "Reset password — CryptoKey";
                _title.Text = "Reset your password";
                _subtitle.Text = "We'll email a reset link. It deep-links back here " +
                    "(cryptokey://) — you'll need your USB key present to finish.";
                _card.Child = Kit.V(12, _emailField);
                SetNext("Send reset email", IconData.ArrowRight);
                break;

            case AuthMode.Reset:
                Title = "Set a new password — CryptoKey";
                _title.Text = "Choose a new password";
                _subtitle.Text = "Setting it here signs you in and re-binds the " +
                    "account verifier — your USB key must be inserted.";
                _card.Child = Kit.V(12,
                    _keyChipRow, _passwordField, _strengthRow, _confirmField, _match);
                SetNext("Set password", IconData.ArrowRight);
                break;

            case AuthMode.Relink:
                Title = "Relink account — CryptoKey";
                _title.Text = "Relink your account";
                _subtitle.Text = "The local account record is missing or unreadable. " +
                    "Sign in online to rewrite it — your USB key must be inserted.";
                _card.Child = Kit.V(12,
                    _keyChipRow, _emailField, _passwordField);
                SetNext("Relink", IconData.ArrowRight);
                break;
        }

        _switchCaption.Text = mode == AuthMode.SignIn ? "New here?" : "Already have one?";
        _switchLink.Content = mode == AuthMode.SignIn
            ? Kit.Label("Create one", null) : Kit.Label("Sign in", null);
        _switchRow.IsVisible = mode is AuthMode.SignIn or AuthMode.Create;
        // Relink (bind a different account, key-fenced) is only meaningful
        // while a record is bound — and only reachable from the sign-in face.
        _relinkLink.IsVisible = mode == AuthMode.SignIn
            && _auth.Record != null;

        _back.IsVisible = mode is AuthMode.Forgot
            || (mode == AuthMode.Create && _auth.State == AuthGateState.Locked);

        FadeBody();
        UpdateNav();
        Control focus = mode is AuthMode.Reset ? _password
            : _email.Text?.Length > 0 ? _password : _email;
        Dispatcher.UIThread.Post(() => focus.Focus());
    }

    /// <summary>120ms fade on mode swaps — gated by the motion setting.</summary>
    private void FadeBody()
    {
        if (!Motion.Enabled)
            return;
        _body.Opacity = 0;
        Dispatcher.UIThread.Post(() => _body.Opacity = 1, DispatcherPriority.Loaded);
    }

    private void SetNext(string text, string? icon)
    {
        _nextText = text;
        _nextIcon = icon;
        Kit.SetLabel(_next, text, icon);
    }

    private void UpdateNav()
    {
        bool emailOk = (_email.Text ?? "").Contains('@');
        bool pwOk = (_password.Text?.Length ?? 0) >= 8;
        bool matchOk = (_confirm.Text?.Length ?? 0) > 0
            && _password.Text == _confirm.Text;
        _next.IsEnabled = _mode switch
        {
            AuthMode.Create => emailOk && pwOk && matchOk,
            AuthMode.SignIn => emailOk && (_password.Text?.Length ?? 0) > 0,
            AuthMode.Forgot => emailOk,
            AuthMode.Reset => pwOk && matchOk,
            AuthMode.Relink => emailOk && (_password.Text?.Length ?? 0) > 0,
            _ => false,
        };
    }

    private static (int score, string text) Strength(string pw)
    {
        if (pw.Length == 0)
            return (0, "");
        int score = 0;
        if (pw.Length >= 12) score++;
        if (pw.Length >= 16) score++;
        if (pw.Any(char.IsUpper) && pw.Any(char.IsLower)) score++;
        if (pw.Any(char.IsDigit)) score++;
        if (pw.Any(c => !char.IsLetterOrDigit(c))) score++;
        return (score, score switch
        {
            <= 1 => "Weak — longer is stronger; 12+ chars recommended.",
            <= 3 => "Okay — 16+ chars or a symbol would strengthen it.",
            _ => "Strong.",
        });
    }

    // ---------------------------------------------------------- errors

    private void ClearErrors()
    {
        _errorBanner.IsVisible = false;
        _email.Classes.Remove("error");
        _password.Classes.Remove("error");
        _confirm.Classes.Remove("error");
    }

    /// <summary>Banner + red field + a brief Locked dip on the key visual.</summary>
    private void Fail(string message, TextBox field)
    {
        _errorBanner.Set(message, Tone.Danger);
        _errorBanner.IsVisible = true;
        field.Classes.Add("error");
        _key.State = KeyVisualState.Locked;
        _ = Task.Run(async () =>
        {
            await Task.Delay(350);
            Dispatcher.UIThread.Post(() =>
            {
                if (_key.State == KeyVisualState.Locked)
                    _key.State = KeyVisualState.Verifying;
            });
        });
    }

    // ---------------------------------------------------------- submit

    private bool _done; // terminal info state shown (email sent / confirm needed)

    private void SetBusy(bool busy, string? label = null)
    {
        _email.IsEnabled = _password.IsEnabled = _confirm.IsEnabled = !busy;
        _forgotLink.IsEnabled = _switchLink.IsEnabled = _back.IsEnabled =
            _pwEye.IsEnabled = _confirmEye.IsEnabled = !busy;
        if (busy)
            Kit.SetLabel(_next, label ?? "Working…", IconData.Refresh);
        else
            Kit.SetLabel(_next, _nextText, _nextIcon);
    }

    private async Task Submit()
    {
        if (_done)
        {
            // The primary button just navigates back to the sign-in face.
            _done = false;
            Show(AuthMode.SignIn);
            return;
        }
        if (!_next.IsEnabled)
            return;
        ClearErrors();
        string email = (_email.Text ?? "").Trim();
        string pw = _password.Text ?? "";
        SetBusy(true, _mode switch
        {
            AuthMode.Create => "Creating account…",
            AuthMode.SignIn => "Signing in…",
            AuthMode.Forgot => "Sending…",
            AuthMode.Reset => "Setting…",
            AuthMode.Relink => "Relinking…",
            _ => "Working…",
        });
        _next.IsEnabled = false;
        _key.State = KeyVisualState.Verifying;

        try
        {
            AuthResult r = _mode switch
            {
                AuthMode.Create => await Task.Run(() => _auth.SignUp(email, pw)),
                AuthMode.SignIn => await Task.Run(() => _auth.SignIn(email, pw)),
                AuthMode.Relink => await Task.Run(() => Relink(email, pw)),
                AuthMode.Forgot => await Task.Run(() => _auth.SendRecovery(email)),
                AuthMode.Reset => await Task.Run(() => Reset(pw)),
                _ => AuthResult.Fail("unknown mode"),
            };
            if (!r.Ok)
            {
                SetBusy(false);
                Fail(r.Error ?? "Failed.", _password);
                UpdateNav();
                return;
            }
            if (r.NeedsConfirm || _mode == AuthMode.Forgot)
            {
                // Terminal info state — _next returns to the sign-in face.
                _done = true;
                _title.Text = r.NeedsConfirm ? "Check your email" : "Reset email sent";
                _subtitle.Text = r.NeedsConfirm
                    ? (r.Error ?? $"Confirm the address Supabase emailed ({email}), then sign in.")
                    : "If that address has an account, a reset link is on its way. " +
                      "Open it on this machine — it deep-links back into this window.";
                var icon = new Icon(r.NeedsConfirm ? IconData.CircleCheck : IconData.Mail, 40)
                {
                    Foreground = r.NeedsConfirm ? Palette.Armed : Palette.Signal,
                    HorizontalAlignment = HorizontalAlignment.Center,
                };
                var line = Kit.Txt(r.NeedsConfirm
                        ? "Confirm your address, then come back and sign in."
                        : "Check your inbox — the link opens this window.",
                    "caption", "dim");
                line.TextAlignment = TextAlignment.Center;
                _card.Child = Kit.V(14, icon, line);
                _switchRow.IsVisible = false;
                _back.IsVisible = false;
                SetBusy(false);
                SetNext("Back to sign in", IconData.ArrowLeft);
                _next.IsEnabled = true;
                FadeBody();
                return;
            }
            _key.State = KeyVisualState.Armed;
            await Task.Delay(250);
            Authenticated = true;
            Close();
        }
        finally
        {
            if (!Authenticated && !_done)
                UpdateNav();
        }
    }

    /// <summary>Relink = online sign-in that rewrites the account record —
    /// allowed to bind a DIFFERENT account (that's the point), so the
    /// enrolled key must be present for the re-attest.</summary>
    private Task<AuthResult> Relink(string email, string password)
    {
        if (_keyPresent?.Invoke() != true)
            return Task.FromResult(AuthResult.Fail(
                "Insert your enrolled USB key — relinking re-attests the account."));
        return _auth.SignIn(email, password, relink: true);
    }

    private Task<AuthResult> Reset(string newPassword)
    {
        if (_keyPresent?.Invoke() != true)
            return Task.FromResult(AuthResult.Fail(
                "Insert your enrolled USB key — the password write re-attests the account."));
        if (_tokenHash == null)
            return Task.FromResult(AuthResult.Fail(
                "No reset token — use the link from the email."));
        return _auth.CompleteRecovery(_tokenHash, newPassword);
    }
}
