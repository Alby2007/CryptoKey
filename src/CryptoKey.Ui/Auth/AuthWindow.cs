using Avalonia;
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
    private readonly string? _tokenHash;

    private readonly KeyVisual _key = new() { Height = 120 };
    private readonly TextBlock _title = Kit.Txt("", "h1");
    private readonly TextBlock _subtitle = Kit.Txt("", "body", "dim");
    private readonly ContentControl _body = new();
    private readonly Button _back;
    private readonly Button _next;
    private readonly TextBlock _error = Kit.Txt("", "caption", "danger");
    private readonly Banner _banner = new() { IsVisible = false };

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
    private readonly TextBlock _strength = Kit.Txt("", "caption", "dim");
    private readonly TextBlock _match = Kit.Txt("", "caption", "dim");

    private AuthMode _mode;

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
        Height = 640;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ExtendClientAreaToDecorationsHint = true;
        ExtendClientAreaTitleBarHeightHint = 36;
        try { Icon = new WindowIcon(host.AppIcon()); }
        catch (Exception) { }

        _back = Kit.Btn("Back", IconData.ArrowLeft, "ghost", () => Show(AuthMode.SignIn));
        _next = Kit.Btn("Continue", IconData.ArrowRight, "primary", () => _ = Submit());
        _next.MinWidth = 150;

        _email.TextChanged += (_, _) => { _error.Text = ""; UpdateNav(); };
        _password.TextChanged += (_, _) =>
        {
            _error.Text = "";
            _strength.Text = _mode is AuthMode.Create or AuthMode.Reset
                ? Strength(_password.Text ?? "")
                : "";
            _match.Text = _mode is AuthMode.Create or AuthMode.Reset
                && (_confirm.Text?.Length ?? 0) > 0
                ? (_password.Text == _confirm.Text ? "Match" : "Passwords don't match")
                : "";
            UpdateNav();
        };
        _confirm.TextChanged += (_, _) =>
        {
            _error.Text = "";
            _match.Text = (_confirm.Text?.Length ?? 0) > 0
                ? (_password.Text == _confirm.Text ? "Match" : "Passwords don't match")
                : "";
            UpdateNav();
        };
        _password.KeyDown += (_, e) =>
        { if (e.Key == Key.Enter && _next.IsEnabled) _ = Submit(); };
        _confirm.KeyDown += (_, e) =>
        { if (e.Key == Key.Enter && _next.IsEnabled) _ = Submit(); };

        var footer = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto") };
        footer.Children.Add(_back);
        var links = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 16,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
        };
        var forgot = Kit.Btn("Forgot password", null, "ghost",
            () => Show(AuthMode.Forgot));
        var switchMode = Kit.Btn("Create one", null, "ghost", () =>
            Show(_mode == AuthMode.SignIn ? AuthMode.Create : AuthMode.SignIn));
        forgot.FontSize = 12;
        switchMode.FontSize = 12;
        links.Children.Add(forgot);
        links.Children.Add(switchMode);
        Grid.SetColumn(links, 1);
        footer.Children.Add(links);
        Grid.SetColumn(_next, 2);
        footer.Children.Add(_next);
        _forgotLink = forgot;
        _switchLink = switchMode;

        _title.TextAlignment = TextAlignment.Center;
        _subtitle.TextAlignment = TextAlignment.Center;
        _subtitle.MaxWidth = 400;
        _subtitle.TextWrapping = TextWrapping.Wrap;
        _subtitle.HorizontalAlignment = HorizontalAlignment.Center;

        var layout = new DockPanel { Margin = new Thickness(36, 40, 36, 24) };
        DockPanel.SetDock(footer, Dock.Bottom);
        layout.Children.Add(footer);
        var head = Kit.V(12, _key, _title, _subtitle, _banner);
        DockPanel.SetDock(head, Dock.Top);
        layout.Children.Add(head);
        DockPanel.SetDock(_error, Dock.Bottom);
        _error.Margin = new Thickness(0, 0, 0, 10);
        _error.TextAlignment = TextAlignment.Center;
        layout.Children.Add(_error);
        _body.Margin = new Thickness(0, 18, 0, 14);
        layout.Children.Add(new ScrollViewer { Content = _body });

        Content = new Grid { Children = { new GridTexture(), layout } };
        Show(mode);
    }

    private readonly Button _forgotLink;
    private readonly Button _switchLink;

    // ---------------------------------------------------------- modes

    private void Show(AuthMode mode)
    {
        _mode = mode;
        _error.Text = "";
        _match.Text = "";
        _strength.Text = "";
        _key.State = KeyVisualState.Verifying;

        bool unconfigured = !_auth.Configured;
        _banner.IsVisible = unconfigured;
        if (unconfigured)
            _banner.Set("supabase.json is missing or invalid — online auth is off. " +
                "Offline unlock still works for a linked account.", Tone.Warn);

        _forgotLink.IsVisible = mode == AuthMode.SignIn;
        _switchLink.IsVisible = mode is AuthMode.SignIn or AuthMode.Create;
        _switchLink.Content = mode == AuthMode.SignIn ? "Create one" : "Sign in";

        switch (mode)
        {
            case AuthMode.Create:
                _title.Text = "Create your CryptoKey account";
                _subtitle.Text = "One account per install — it gates this dashboard and " +
                    "sensitive commands. Your USB key stays the real lock.";
                _body.Content = Kit.V(10, _email, _password, _strength, _confirm, _match);
                Kit.SetLabel(_next, "Create account", IconData.ArrowRight);
                break;

            case AuthMode.SignIn:
                _title.Text = "Sign in to CryptoKey";
                _subtitle.Text = _auth.State == AuthGateState.Locked
                    ? "The dashboard unlocks for this session after sign-in. " +
                      "Offline? The same password still works."
                    : "Sign in once — the dashboard and sensitive commands open " +
                      "for the rest of this session.";
                _email.Text = _auth.Record?.Email ?? _email.Text;
                _body.Content = Kit.V(10, _email, _password);
                Kit.SetLabel(_next, "Sign in", IconData.ArrowRight);
                break;

            case AuthMode.Forgot:
                _title.Text = "Reset your password";
                _subtitle.Text = "We'll email a reset link. It deep-links back here " +
                    "(cryptokey://) — you'll need your USB key present to finish.";
                _body.Content = Kit.V(10, _email);
                Kit.SetLabel(_next, "Send reset email", IconData.ArrowRight);
                break;

            case AuthMode.Reset:
                _title.Text = "Choose a new password";
                _subtitle.Text = "Setting it here signs you in and re-binds the " +
                    "account verifier — your USB key must be inserted.";
                _body.Content = Kit.V(10, _password, _strength, _confirm, _match);
                Kit.SetLabel(_next, "Set password", IconData.ArrowRight);
                break;

            case AuthMode.Relink:
                _title.Text = "Relink your account";
                _subtitle.Text = "The local account record is missing or unreadable. " +
                    "Sign in online to rewrite it — your USB key must be inserted.";
                _body.Content = Kit.V(10, _email, _password);
                Kit.SetLabel(_next, "Relink", IconData.ArrowRight);
                break;
        }

        _back.IsVisible = mode is AuthMode.Forgot
            || (mode == AuthMode.Create && _auth.State == AuthGateState.Locked);
        UpdateNav();
        Control focus = mode is AuthMode.Reset ? _password
            : _email.Text?.Length > 0 ? _password : _email;
        Dispatcher.UIThread.Post(() => focus.Focus());
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

    private static string Strength(string pw)
    {
        if (pw.Length == 0)
            return "";
        int score = 0;
        if (pw.Length >= 12) score++;
        if (pw.Length >= 16) score++;
        if (pw.Any(char.IsUpper) && pw.Any(char.IsLower)) score++;
        if (pw.Any(char.IsDigit)) score++;
        if (pw.Any(c => !char.IsLetterOrDigit(c))) score++;
        return score switch
        {
            <= 1 => "Weak — longer is stronger; 12+ chars recommended.",
            <= 3 => "Okay — 16+ chars or a symbol would strengthen it.",
            _ => "Strong.",
        };
    }

    // ---------------------------------------------------------- submit

    private bool _done; // terminal info state shown (email sent / confirm needed)

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
        _next.IsEnabled = false;
        _error.Text = "";
        string email = (_email.Text ?? "").Trim();
        string pw = _password.Text ?? "";

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
                _error.Text = r.Error ?? "Failed.";
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
                _body.Content = Kit.V(10);
                _forgotLink.IsVisible = false;
                _switchLink.IsVisible = false;
                _back.IsVisible = false;
                Kit.SetLabel(_next, "Back to sign in", IconData.ArrowLeft);
                _next.IsEnabled = true;
                return;
            }
            Authenticated = true;
            Close();
        }
        finally
        {
            if (!Authenticated && !_done)
                UpdateNav();
        }
    }

    /// <summary>Relink = online sign-in that rewrites the account record.</summary>
    private Task<AuthResult> Relink(string email, string password)
    {
        if (_keyPresent?.Invoke() == false)
            return Task.FromResult(AuthResult.Fail(
                "Insert your enrolled USB key — relinking re-attests the account."));
        return _auth.SignIn(email, password);
    }

    private Task<AuthResult> Reset(string newPassword)
    {
        if (_keyPresent?.Invoke() == false)
            return Task.FromResult(AuthResult.Fail(
                "Insert your enrolled USB key — the password write re-attests the account."));
        if (_tokenHash == null)
            return Task.FromResult(AuthResult.Fail(
                "No reset token — use the link from the email."));
        return _auth.CompleteRecovery(_tokenHash, newPassword);
    }
}
