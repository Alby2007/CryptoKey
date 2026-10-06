using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace CryptoKey.Ui;

/// <summary>
/// The account page: who is signed in, what the account does (and does
/// NOT) do, sign-out, and password change. Plain-spoken copy is the point
/// — the account is an application/dashboard gate, not an OS lock factor.
/// </summary>
internal sealed class AccountPage : Page
{
    private readonly TextBlock _who = Kit.Txt("", "title");
    private readonly TextBlock _uid = Kit.Txt("", "mono", "dim");
    private readonly StatusChip _state = new();
    private readonly Banner _banner = new() { IsVisible = false };

    private readonly TextBox _current = new()
    {
        Watermark = "Current password",
        PasswordChar = '●',
        Classes = { "field" },
        MaxWidth = 320,
    };
    private readonly TextBox _newPw = new()
    {
        Watermark = "New password (8+ characters)",
        PasswordChar = '●',
        Classes = { "field" },
        MaxWidth = 320,
    };
    private readonly TextBox _confirmPw = new()
    {
        Watermark = "Repeat new password",
        PasswordChar = '●',
        Classes = { "field" },
        MaxWidth = 320,
    };
    private readonly Button _change;
    private readonly Button _signOut;
    private readonly Panel _linked;
    private readonly Panel _unlinked;

    public AccountPage(PageContext ctx) : base(ctx)
    {
        _change = Kit.Btn("Change password", IconData.Key, "primary",
            () => _ = ChangePassword());
        _change.IsEnabled = false;
        _newPw.TextChanged += (_, _) => UpdateChangeGate();
        _confirmPw.TextChanged += (_, _) => UpdateChangeGate();
        _signOut = Kit.Btn("Sign out", IconData.Quit, "danger",
            () => _ = SignOut());

        var create = Kit.Btn("Create account", IconData.Person, "primary",
            () => Ctx.ShowAuth(_ => Refresh(), AuthMode.Create));
        var signIn = Kit.Btn("Sign in to an existing account", IconData.Key, "ghost",
            () => Ctx.ShowAuth(_ => Refresh(), AuthMode.SignIn));

        _unlinked = Kit.V(14,
            Kit.Section("No account linked", IconData.Person,
                "This install isn't bound to an account — sensitive commands stay open " +
                "until one is.",
                Kit.H(10, create, signIn)),
            Kit.Section("What an account is", IconData.Shield, null,
                Kit.V(10,
                    Kit.Txt(
                        "An optional gate for the CryptoKey dashboard and sensitive " +
                        "commands — never a workstation lock factor.", "body"),
                    Kit.Txt(
                        "Pulling your USB key still locks this machine with or without a " +
                        "sign-in, and the recovery phrase still unlocks it. The account " +
                        "adds a second gate on the app surface only.", "body", "dim"))));

        _linked = Kit.V(14,
            Kit.Section("Signed in", IconData.Person, null,
                Kit.Row("Email", "The account bound to this install.", _who),
                Kit.Row("User ID", null, _uid),
                Kit.Row("Session", null, _state)),
            Kit.Section("What this account is", IconData.Shield, null,
                Kit.V(10,
                    Kit.Txt(
                        "A gate for the CryptoKey dashboard and sensitive commands — " +
                        "not a workstation lock factor.", "body"),
                    Kit.Txt(
                        "Pulling your USB key still locks this machine with or without a " +
                        "sign-in, and the recovery phrase still unlocks it. The dashboard " +
                        "stays unlocked for the rest of this session only.", "body", "dim"))),
            Kit.Section("Change password", IconData.Key,
                "Needs the enrolled key inserted — the new verifier re-attests on the next key verify.",
                Kit.V(10, _current, _newPw, _confirmPw, _change)),
            Kit.Section("Sign out", IconData.Quit,
                "Ends this session — gated commands ask for the password again.",
                _signOut));

        Content = Kit.PageScroll(Kit.V(14,
            Kit.PageHeader("Account", "The identity that gates this dashboard and sensitive commands."),
            _banner,
            _unlinked,
            _linked));
    }

    private void UpdateChangeGate()
        => _change.IsEnabled = (_newPw.Text?.Length ?? 0) >= 8
            && _newPw.Text == _confirmPw.Text
            && (_current.Text?.Length ?? 0) > 0;

    public override void Refresh()
    {
        var auth = AuthService.Current;
        AccountRecord? rec = auth.Record;
        _who.Text = rec?.Email ?? "—";
        _uid.Text = rec?.UserId ?? "—";
        _state.Set(auth.State switch
        {
            AuthGateState.Online => "signed in",
            AuthGateState.OfflineUnlocked => "unlocked (offline)",
            AuthGateState.Locked => "locked",
            AuthGateState.Unenrolled => "no account",
            _ => "unconfigured",
        }, auth.State switch
        {
            AuthGateState.Online => Tone.Ok,
            AuthGateState.OfflineUnlocked => Tone.Ok,
            AuthGateState.Locked => Tone.Warn,
            _ => Tone.Neutral,
        });
        _linked.IsVisible = rec != null;
        _unlinked.IsVisible = rec == null;
        bool noConfig = !auth.Configured;
        _banner.IsVisible = noConfig;
        if (noConfig)
            _banner.Set("supabase.json is missing or invalid — online sign-in " +
                "and password recovery are off; the local verifier still works.", Tone.Warn);
        _signOut.IsEnabled = auth.Authorized;
    }

    private async Task ChangePassword()
    {
        string cur = _current.Text ?? "";
        string next = _newPw.Text ?? "";
        // Key present is required — the verifier write must re-attest.
        if (!Client.Snapshot.KeyPresent)
        {
            Ctx.Toast("Insert your enrolled USB key — the password change re-attests the account.", true);
            return;
        }
        AuthResult r = await Task.Run(
            () => AuthService.Current.ChangePassword(cur, next));
        if (r.Ok)
        {
            _current.Text = "";
            _newPw.Text = "";
            _confirmPw.Text = "";
            Ctx.Toast("Password changed — verifier re-attests on the next key verify.", false);
        }
        else
        {
            Ctx.Toast(r.Error ?? "Password change failed.", true);
        }
        Refresh();
    }

    private async Task SignOut()
    {
        await Task.Run(() => AuthService.Current.SignOut());
        Ctx.Toast("Signed out — this session's authorization ended.", false);
        Refresh();
    }

    protected override void OnHidden()
    {
        _current.Text = "";
        _newPw.Text = "";
        _confirmPw.Text = "";
    }
}
