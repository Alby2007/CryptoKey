using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace CryptoKey.Ui;

/// <summary>
/// Key &amp; Recovery: the enrolled key's live verification (repair /
/// re-enroll) and a guided recovery-phrase regeneration — authorize with
/// the current phrase OR the freshly verified key, see the new phrase once,
/// retype it, done.
/// </summary>
internal sealed class KeyPage : Page
{
    // ---- Enrolled key ----
    private readonly TextBlock _keyStatus = Kit.Txt("Checking key…", "h2");
    private readonly TextBlock _keyDetail = Kit.Txt("", "mono", "dim");
    private readonly Button _repair;
    private bool _needsRepair;

    // ---- Remove key ----
    private readonly StackPanel _enrolledBody;
    private readonly StackPanel _unenrolledBody;
    private readonly Grid _removeRow;
    private readonly Grid _vaultBlockRow;
    private readonly Border _removeWell;
    private readonly TextBox _removePhrase = PhraseBox("Recovery phrase");
    private readonly HoldButton _removeBtn;

    // ---- Phrase flow ----
    private readonly Border _stepAuth;
    private readonly Border _stepReveal;
    private readonly TextBox _current = PhraseBox("Current recovery phrase (or attach your key)");
    private readonly TextBox _retype = PhraseBox("Retype the new phrase");
    private readonly TextBlock _phrase = new()
    {
        FontSize = 26,
        FontWeight = FontWeight.Bold,
        LetterSpacing = 2,
        TextAlignment = TextAlignment.Center,
        TextWrapping = TextWrapping.Wrap,
        Foreground = Palette.Armed,
    };
    private readonly CheckBox _wroteIt = new() { Content = "I've written it down somewhere safe" };
    private readonly Button _generate;
    private readonly Button _confirm;
    private readonly TextBlock _flowStatus = Kit.Txt("", "caption", "dim");
    private readonly TextBlock[] _steps = new TextBlock[3];
    private string? _pending;

    public KeyPage(PageContext ctx) : base(ctx)
    {
        _repair = Kit.Btn("Repair keyfile", IconData.Wrench, "", Repair);
        _repair.IsEnabled = false;

        _removeBtn = new HoldButton("Remove key", IconData.Trash, "Hold to remove the key");
        _removeBtn.Confirmed += RemoveKey;
        var removeWell = new Border { Classes = { "well" }, IsVisible = false };
        removeWell.Child = Kit.V(10,
            Kit.Txt("This disarms auto-lock — pulling the drive then does nothing " +
                    "until a new key is set up. The recovery phrase stays (it still " +
                    "unlocks a manual lock and can recover a vault), as do your " +
                    "account and settings.", "body", "dim"),
            _removePhrase,
            Kit.H(8, _removeBtn,
                Kit.Btn("Cancel", null, "ghost", () =>
                {
                    removeWell.IsVisible = false;
                    _removePhrase.Text = "";
                })));
        _removeWell = removeWell;
        _removeRow = Kit.Row("Remove key",
            "Unbind this drive — the install, account, and recovery phrase all stay.",
            Kit.Btn("Remove key…", IconData.Trash, "", () =>
            {
                _removeWell.IsVisible = !_removeWell.IsVisible;
                if (_removeWell.IsVisible)
                    _removePhrase.Focus();
            }));
        _vaultBlockRow = Kit.Row("Remove key",
            "A vault image exists — its contents are keyed to this enrollment. " +
            "Remove the vault first.",
            Kit.Btn("Open vault page", IconData.ArrowRight, "ghost",
                () => Ctx.Navigate(Route.Vault)));
        _removeRow.IsVisible = _vaultBlockRow.IsVisible = false;

        _enrolledBody = Kit.V(14,
            Kit.V(6, _keyStatus, _keyDetail),
            Kit.Row("Re-enroll", "Register a different drive (or start fresh). Runs the setup wizard.",
                Kit.Btn("Re-enroll a key", IconData.Refresh, "", () => Ctx.OpenOnboarding())),
            Kit.Row("Repair keyfile", "Rewrites a damaged or outdated keyfile on the enrolled drive.",
                Kit.H(8, Kit.Btn("Re-check", IconData.Scan, "ghost", RefreshKey), _repair)),
            _removeRow,
            _vaultBlockRow);
        var setupBtn = Kit.Btn("Set up a key", IconData.Usb, "primary", () => Ctx.OpenOnboarding());
        setupBtn.HorizontalAlignment = HorizontalAlignment.Left;
        _unenrolledBody = Kit.V(8,
            Kit.Txt("No key enrolled — protection is off", "h2"),
            Kit.Txt("Pulling a drive does nothing until a key is set up. Your " +
                    "recovery phrase, account, and settings are all kept.",
                "body", "dim"),
            setupBtn);

        var keyCard = Kit.Section("Enrolled key", IconData.Usb,
            "Live check of the drive registered as your key.",
            _enrolledBody, _unenrolledBody, _removeWell);

        // ---- Step 1: authorize ----
        _generate = Kit.Btn("Generate new phrase", IconData.Sparkles, "primary", Generate);
        _current.KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Enter)
                Generate();
        };
        _stepAuth = new Border
        {
            Classes = { "well" },
            Child = Kit.V(12,
                Kit.Txt("Generated, not chosen — the failsafe when your key isn't attached. " +
                        "Authorize with your current phrase, or just attach the enrolled key.",
                    "body", "dim"),
                _current,
                _generate),
        };

        // ---- Step 2: reveal + confirm ----
        _confirm = Kit.Btn("Save new phrase", IconData.Check, "primary", Confirm);
        _confirm.IsEnabled = false;
        _wroteIt.IsCheckedChanged += (_, _) => UpdateConfirm();
        _retype.TextChanged += (_, _) =>
        {
            _retype.Classes.Remove("error");
            UpdateConfirm();
        };
        _retype.KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Enter && _confirm.IsEnabled)
                Confirm();
        };
        var phraseWell = new Border
        {
            Background = Palette.CarbonDeep,
            BorderBrush = Palette.Brush(DesignTokens.Armed, 0x55),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(18, 22),
            Child = Kit.V(8, Kit.Txt("YOUR NEW RECOVERY PHRASE — SHOWN ONCE", "eyebrow"), _phrase),
        };
        _phrase.FontFamily = Palette.Mono;
        _stepReveal = new Border
        {
            Classes = { "well" },
            IsVisible = false,
            Child = Kit.V(12,
                phraseWell,
                _wroteIt,
                _retype,
                Kit.H(8, _confirm, Kit.Btn("Cancel", null, "ghost", ResetFlow))),
        };

        var stepper = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 18 };
        string[] names = { "1  Authorize", "2  Write it down", "3  Confirm" };
        for (int i = 0; i < 3; i++)
        {
            _steps[i] = Kit.Txt(names[i], "caption");
            _steps[i].FontWeight = FontWeight.SemiBold;
            stepper.Children.Add(_steps[i]);
        }

        var phraseCard = Kit.Section("Recovery phrase", IconData.FileKey,
            "Old phrases stop working the moment a new one is saved.",
            Kit.V(14, stepper, _stepAuth, _stepReveal, _flowStatus));

        Content = Kit.PageScroll(Kit.V(16,
            Kit.PageHeader("Key & Recovery", "Your physical key and the phrase that stands in for it."),
            keyCard, phraseCard));
        SetStep(0);
    }

    private static TextBox PhraseBox(string watermark) => new()
    {
        Watermark = watermark,
        PasswordChar = '•',
        Classes = { "phrase" },
        RevealPassword = false,
    };

    private bool? _shownEnrolled;

    public override void Refresh()
    {
        bool enrolled = Client.Snapshot.Enrolled;
        _enrolledBody.IsVisible = enrolled;
        _unenrolledBody.IsVisible = !enrolled;
        if (_shownEnrolled != enrolled)
        {
            bool first = _shownEnrolled == null;
            _shownEnrolled = enrolled;
            // Enrollment flipped while the page sat open — repopulate rows.
            if (!first)
                RefreshKey();
        }
        _repair.IsEnabled = _needsRepair && Client.Snapshot.State != GuardState.Locked;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        RefreshKey();
    }

    protected override void OnHidden() => ResetFlow();

    // ---------------------------------------------------------- key status

    private async void RefreshKey()
    {
        _removeWell.IsVisible = false;
        _removePhrase.Text = "";
        if (!Client.Snapshot.Enrolled)
        {
            // Dormant — no key to check, nothing to remove.
            _needsRepair = false;
            _removeRow.IsVisible = _vaultBlockRow.IsVisible = false;
            Refresh();
            return;
        }
        _keyStatus.Text = "Checking key…";
        _keyStatus.Foreground = Palette.TextDim;
        _keyDetail.Text = "";
        // A vault image is keyed to this enrollment — the engine refuses
        // removal while one exists, so the row swaps to a Vault-page pointer.
        bool vaultImageExists = await Client.Query((s, _) => s.Vault.ImageExists);
        _removeRow.IsVisible = !vaultImageExists;
        _vaultBlockRow.IsVisible = vaultImageExists;
        string serial = Client.Settings.DeviceSerial;
        string status, detail;
        bool needsRepair = false, present = false;
        try
        {
            // WMI is slow — find the disk off every pump; verify on the engine.
            UsbDisk? disk = await Task.Run(() => Platform.Services.Usb.FindDisk(serial));
            if (disk == null)
            {
                status = "Key absent";
                detail = $"serial {serial}";
            }
            else
            {
                (bool ok, string why) = await Client.Query((_, cfg) =>
                    (KeyVerifier.Verify(cfg, disk, out string w), w));
                string vols = disk.VolumePaths.Count > 0 ? string.Join(", ", disk.VolumePaths) : "no mounted volume";
                status = ok ? $"Present — {why}" : $"Present but failing — {why}";
                detail = $"{disk.Model} on {vols} · serial {serial}";
                needsRepair = !ok;
                present = ok;
            }
        }
        catch (Exception ex)
        {
            status = "Couldn't check the key";
            detail = ex.Message;
        }
        _keyStatus.Text = status;
        _keyStatus.Foreground = present ? Palette.Armed : needsRepair ? Palette.Paused : Palette.TextDim;
        _keyDetail.Text = detail;
        _needsRepair = needsRepair;
        Refresh();
    }

    private async void Repair()
    {
        _repair.IsEnabled = false;
        bool ok = await Client.Query((s, _) =>
        {
            try { return s.RepairKeyfile(); }
            catch (Exception) { return false; }
        });
        Report(ok ? null : "Repair failed — key absent or write error", "Keyfile repaired — key re-armed");
        RefreshKey();
    }

    /// <summary>
    /// Remove the key binding — the hold is the deliberation, the phrase is
    /// the ownership proof, the account session gates it like every other
    /// mutator (<see cref="GuardClient.Unenroll"/>).
    /// </summary>
    private async void RemoveKey()
    {
        _removeBtn.IsEnabled = false;
        string reply = await Client.Unenroll(_removePhrase.Text ?? "");
        _removeBtn.IsEnabled = true;
        if (reply.StartsWith("ok", StringComparison.Ordinal))
        {
            _removePhrase.Text = "";
            _removeWell.IsVisible = false;
            Ctx.Toast("Key removed — auto-lock is off until a new key is set up.", false);
            RefreshKey();
            return;
        }
        if (reply.Contains("AUTH_REQUIRED", StringComparison.Ordinal))
        {
            // The session's fresh window closed — re-authenticate and retry.
            Ctx.ShowAuth(ok => { if (ok) RemoveKey(); }, AuthMode.SignIn);
            return;
        }
        _removePhrase.Classes.Add("error");
        Report(reply.StartsWith("err ", StringComparison.Ordinal) ? reply[4..] : reply);
    }

    // ---------------------------------------------------------- phrase flow

    private void SetStep(int step)
    {
        for (int i = 0; i < _steps.Length; i++)
            _steps[i].Foreground = i == step ? Palette.Signal : i < step ? Palette.Armed : Palette.TextFaint;
        _stepAuth.IsVisible = step == 0;
        _stepReveal.IsVisible = step > 0;
    }

    /// <summary>
    /// Regeneration is gated two ways: the current credential, OR a freshly
    /// verified enrolled key (Current generation only — a stale keyfile is
    /// clone-suspect and must not authorize a credential reset).
    /// </summary>
    private async void Generate()
    {
        if (!_generate.IsEnabled)
            return;
        _generate.IsEnabled = false;
        Status("Verifying…", Tone.Neutral);
        string current = _current.Text ?? "";
        string serial = Client.Settings.DeviceSerial;
        bool ok;
        try
        {
            // Detached copy for the slow PBKDF2 — the engine never blocks on it.
            string json = await Client.Query((_, cfg) => JsonSerializer.Serialize(cfg));
            KeyConfig copy = JsonSerializer.Deserialize<KeyConfig>(json)!;
            ok = await Task.Run(() =>
            {
                if (current.Length > 0 && ConfigStore.VerifyPassphrase(copy, current))
                    return true;
                UsbDisk? disk = Platform.Services.Usb.FindDisk(serial);
                return disk != null && KeyVerifier.Check(copy, disk).Match == SecretMatch.Current;
            });
        }
        catch (Exception)
        {
            ok = false;
        }
        _generate.IsEnabled = true;
        if (!ok)
        {
            _current.Classes.Add("error");
            Status("Enter the current phrase, or attach your enrolled key.", Tone.Danger);
            Ctx.Toast("Enter the current phrase, or attach your enrolled key.", true);
            return;
        }
        _current.Classes.Remove("error");
        _current.Text = "";
        _pending = RecoveryPhrase.Generate();
        _phrase.Text = _pending;
        _wroteIt.IsChecked = false;
        _retype.Text = "";
        SetStep(1);
        Status("Write it on paper, not in a file on this machine. Then retype it below.", Tone.Warn);
    }

    private void UpdateConfirm()
    {
        bool wrote = _wroteIt.IsChecked == true;
        _confirm.IsEnabled = _pending != null && wrote && (_retype.Text?.Length ?? 0) > 0;
        if (_pending != null)
            SetStep(wrote ? 2 : 1);
    }

    private async void Confirm()
    {
        if (_pending == null)
            return;
        if (!Matches(_pending, _retype.Text ?? ""))
        {
            _retype.Classes.Add("error");
            Status("That doesn't match the phrase shown — check each group.", Tone.Danger);
            return;
        }
        string pending = _pending;
        _confirm.IsEnabled = false;
        (string? err, bool reattested) = await Client.Query<(string?, bool)>((svc, cfg) =>
        {
            ConfigStore.ChangePassphrase(cfg, pending);
            try
            {
                ConfigStore.Save(cfg);
            }
            catch (Exception ex)
            {
                return ($"Save failed: {ex.Message}", false);
            }
            // The attestation MAC covers the phrase hash — re-attest now if
            // the key is present; otherwise flag the change as ours so the
            // next insert re-binds quietly instead of announcing tamper.
            bool re;
            try { re = svc.RotateNow(); }
            catch (Exception) { re = false; }
            if (!re)
                svc.MarkConfigDirty();
            return (null, re);
        });
        if (!Report(err))
        {
            _confirm.IsEnabled = true;
            return;
        }
        string done = reattested
            ? "Recovery phrase updated — key re-attested."
            : "Recovery phrase updated — key will re-attest on next insert.";
        ResetFlow();
        Status(done, Tone.Ok);
        Ctx.Toast(done, false);
    }

    private static bool Matches(string want, string typed)
    {
        Span<char> a = stackalloc char[64];
        Span<char> b = stackalloc char[64];
        try
        {
            int al = RecoveryPhrase.Normalize(want.AsSpan(), a);
            int bl = RecoveryPhrase.Normalize(typed.AsSpan(), b);
            return al == bl && a[..al].SequenceEqual(b[..bl]);
        }
        finally
        {
            a.Clear();
            b.Clear();
        }
    }

    private void ResetFlow()
    {
        _pending = null;
        _phrase.Text = "";
        _current.Text = "";
        _retype.Text = "";
        _wroteIt.IsChecked = false;
        _current.Classes.Remove("error");
        _retype.Classes.Remove("error");
        Status("", Tone.Neutral);
        SetStep(0);
    }

    private void Status(string text, Tone tone)
    {
        _flowStatus.Text = text;
        _flowStatus.Foreground = tone == Tone.Neutral ? Palette.TextDim : Kit.ToneBrush(tone);
    }
}
