using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Threading;

namespace CryptoKey.Ui;

/// <summary>
/// The encrypted vault: state hero with usage ring and context actions,
/// settings, TPM machine binding, and a hold-to-confirm danger zone. State
/// logic is <see cref="VaultPresenter"/> (the legacy ladder, unchanged).
/// </summary>
internal sealed class VaultPage : Page
{
    private readonly StatusChip _badge = new();
    private readonly TextBlock _title = Kit.Txt("", "h2");
    private readonly TextBlock _detail = Kit.Txt("", "body", "dim");
    private readonly UsageRing _ring = new();
    private readonly TextBlock _usage = Kit.Txt("", "caption", "dim");
    private readonly StackPanel _ringBox;
    private readonly Banner _driver = new();

    private readonly StackPanel _createRow;
    private readonly Slider _size = new() { Minimum = 64, Maximum = 8192, SmallChange = 64, LargeChange = 512, TickFrequency = 64, IsSnapToTickEnabled = true, Width = 260 };
    private readonly TextBlock _sizeText = Kit.Txt("", "title");
    private readonly Button _create;

    private readonly StackPanel _actions;
    private readonly Button _mount;
    private readonly HoldButton _accept;
    private readonly Button _open;
    private readonly Button _close;

    private readonly ToggleSwitch _autoMount;
    private readonly Button _rekey;
    private readonly SettingCombo _letter = new() { MinWidth = 110 };
    private readonly TextBlock _imagePath = Kit.Txt("", "mono", "dim");
    private readonly Slider _idle = new() { Minimum = 0, Maximum = 60, SmallChange = 1, TickFrequency = 1, IsSnapToTickEnabled = true, Width = 220 };
    private readonly TextBlock _idleText = Kit.Txt("", "mono", "dim");
    private readonly DispatcherTimer _idleSave;

    private readonly Border _tpmCard;
    private readonly TextBox _tpmPhrase = new() { Watermark = "Recovery phrase", PasswordChar = '•', Classes = { "phrase" }, Width = 300 };
    private readonly ToggleSwitch _strict = new();
    private readonly Control _strictRow;
    private readonly Button _tpmBtn;
    private readonly HoldButton _unbind;
    private TpmAction _tpmAction;

    private readonly HoldButton _reformat;
    private readonly HoldButton _delete;

    private VaultFacts? _facts;
    private int _refreshSeq;
    private bool _syncing;
    private bool _sizeInit;

    public VaultPage(PageContext ctx) : base(ctx)
    {
        if (!ctx.Caps.Vault)
        {
            var b = new Banner();
            b.Set($"The encrypted vault needs the Dokany driver — {ctx.Caps.Unavailable}.", Tone.Neutral);
            Content = Kit.PageScroll(Kit.V(16,
                Kit.PageHeader("Vault", "An encrypted drive that only exists while your key is in."), b));
            _ringBox = _createRow = _actions = new StackPanel();
            _create = _mount = _open = _close = _tpmBtn = _rekey = new Button();
            _accept = _unbind = _reformat = _delete = new HoldButton("", IconData.Close);
            _autoMount = new ToggleSwitch();
            _tpmCard = new Border();
            _strictRow = new Border();
            _idleSave = new DispatcherTimer();
            return;
        }

        // ---- Hero ----
        _ringBox = Kit.V(6, _ring, _usage);
        _ringBox.HorizontalAlignment = HorizontalAlignment.Center;
        _usage.TextAlignment = Avalonia.Media.TextAlignment.Center;

        _size.ValueChanged += (_, _) => UpdateSizeText();
        _create = Kit.Btn("Create vault", IconData.Vault, "primary", CreateVault);
        _createRow = Kit.H(14, _sizeText, _size, _create);
        _sizeText.VerticalAlignment = _size.VerticalAlignment = VerticalAlignment.Center;
        _sizeText.Width = 110;

        _mount = Kit.Btn("Mount", IconData.Play, "primary", ToggleMount);
        _accept = new HoldButton("Accept rolled-back state", IconData.Check,
            "Hold to accept — ratifying an older image is irreversible");
        _accept.Confirmed += AcceptRollback;
        _open = Kit.Btn("Open in file manager", IconData.Folder, "", OpenDrive);
        _close = Kit.Btn("Close vault", IconData.Close, "ghost", CloseVault);
        _rekey = Kit.Btn("Rekey", IconData.Refresh, "", Rekey);
        _actions = Kit.H(10, _mount, _accept, _open, _close);

        var heroText = Kit.V(10, _badge, _title, _detail, _driver, _createRow, _actions);
        _badge.HorizontalAlignment = HorizontalAlignment.Left;
        var heroGrid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), ColumnSpacing = 24 };
        heroGrid.Children.Add(heroText);
        Grid.SetColumn(_ringBox, 1);
        heroGrid.Children.Add(_ringBox);
        var hero = new Border { Classes = { "card" }, Padding = new Thickness(24), Child = heroGrid };

        // ---- Settings ----
        _autoMount = Kit.Toggle(false, on => { if (!_syncing) Save(g => g.VaultAutoMount = on); });
        // Only an explicit pick from the open list persists — never an
        // init-time selection resolve or a stray mouse-wheel tick.
        _letter.Committed += async item =>
        {
            if (_syncing || item is not string letter || letter == _facts?.ConfiguredMountPoint)
                return;
            await Client.Run((s, cfg) =>
            {
                s.Vault.ApplyMountPoint(letter);
                ConfigStore.Save(cfg);
                s.MarkConfigDirty();
            });
            Ctx.Toast($"Vault letter → {letter} (applies on next mount)", false);
        };
        _imagePath.TextWrapping = Avalonia.Media.TextWrapping.Wrap;
        _idleSave = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _idleSave.Tick += (_, _) =>
        {
            _idleSave.Stop();
            int v = (int)_idle.Value;
            // VaultIdleMinutes is in the attest set — the save flags the re-attest.
            Save(g => g.VaultIdleMinutes = v);
        };
        _idle.ValueChanged += (_, _) =>
        {
            _idleText.Text = ProtectionPresenter.IdleText((int)_idle.Value);
            if (_syncing || !Kit.UserDriven(_idle))
                return;
            _idleSave.Stop();
            _idleSave.Start(); // drags fire per-tick — debounce the write
        };
        var settings = Kit.Section("Vault settings", IconData.Settings, null,
            Kit.Row("Mount automatically", "Open the drive as soon as your key verifies.", _autoMount),
            Kit.Row("Drive letter", "Where the vault appears when mounted.", _letter),
            Kit.Row("Image file", null, Kit.Btn("Show file", IconData.Folder, "ghost small",
                () => Ctx.Host.RevealFile(_facts?.ImagePath ?? ""))),
            _imagePath,
            Kit.Row("Seal after idle", "Dismount and drop keys after this much inactivity.",
                Kit.H(12, _idle, _idleText)),
            Kit.Row("Rotate volume key",
                "Re-encrypt every chunk under a fresh key — old ciphertext snapshots die. The vault re-opens around the swap.",
                _rekey));
        _imagePath.Margin = new Thickness(0, -6, 0, 12);

        // ---- Machine binding ----
        _tpmBtn = Kit.Btn("Bind to this machine", IconData.Cpu, "primary", TpmPrimary);
        _unbind = new HoldButton("Unbind", IconData.Close, "Hold to unbind — the image will open on any machine");
        _unbind.Confirmed += Unbind;
        _strict = new ToggleSwitch();
        _strictRow = Kit.Row("Strict binding", "No phrase recovery: a TPM clear means reformat.", _strict);
        _tpmCard = Kit.Section("Machine binding", IconData.Cpu,
            "TPM-seal the vault to this PC — a copied image won't open anywhere else.",
            Kit.Row("Recovery phrase", "Authorizes the binding and seals a recovery copy.", _tpmPhrase),
            _strictRow,
            Kit.H(10, _tpmBtn, _unbind));

        // ---- Danger zone ----
        _reformat = new HoldButton("Reformat vault", IconData.Refresh, "Hold to wipe — previous contents are gone");
        _reformat.Confirmed += Reformat;
        _delete = new HoldButton("Delete image", IconData.Trash, "Hold to delete the vault image file");
        _delete.Confirmed += DeleteImage;
        var danger = Kit.Section("Danger zone", IconData.Warning, "Press and hold to confirm.",
            Kit.Row("Reformat", "A fresh empty image at the size above.", _reformat),
            Kit.Row("Delete image", "Removes the vault file from disk.", _delete));

        var note = Kit.Txt("The vault only exists while your key is in — pull the key or lock the session and the " +
                           "drive force-dismounts. Two missed secret rotations seal it permanently (same window as the " +
                           "keyfile).", "caption", "faint");

        Content = Kit.PageScroll(Kit.V(16,
            Kit.PageHeader("Vault", "An encrypted drive that only exists while your key is in."),
            hero, settings, _tpmCard, danger, note));
    }

    private void UpdateSizeText()
    {
        int mb = (int)_size.Value;
        _sizeText.Text = mb >= 1024 ? $"Size · {mb / 1024.0:0.#} GB" : $"Size · {mb} MB";
    }

    public override async void Refresh()
    {
        if (!Ctx.Caps.Vault)
            return;
        int seq = ++_refreshSeq;
        VaultFacts f = await Client.Query(VaultFacts.Gather);
        if (seq != _refreshSeq)
            return; // a newer refresh superseded this one
        _facts = f;
        Apply(f);
    }

    private void Apply(VaultFacts f)
    {
        VaultView v = VaultPresenter.Present(f);
        _syncing = true;
        try
        {
            _badge.Set(v.Badge, v.Tone);
            _title.Text = v.Title;
            _detail.Text = v.Detail;
            _ringBox.IsVisible = v.ShowUsage;
            _ring.Fraction = v.UsageFraction;
            _usage.Text = v.UsageText;

            _driver.IsVisible = v.DriverNote != null;
            if (v.DriverNote != null)
            {
                _driver.Set(v.DriverNote, Tone.Warn);
                _driver.SetAction(Kit.Btn("Get Dokany", IconData.External, "small",
                    () => Ctx.Host.OpenUrl("https://dokan-dev.github.io")));
            }

            _createRow.IsVisible = v.ShowCreate;
            _create.IsEnabled = v.CreateEnabled;
            Kit.SetLabel(_create, v.CreateText, IconData.Vault);
            _size.IsEnabled = v.CreateEnabled;
            if (!_sizeInit)
            {
                _size.Value = Math.Clamp(f.SizeMb, 64, 8192);
                _sizeInit = true;
            }
            UpdateSizeText();

            _actions.IsVisible = v.ShowActions;
            _mount.IsVisible = v.MountVisible && !v.MountIsAcceptRollback;
            _accept.IsVisible = v.MountIsAcceptRollback;
            _mount.IsEnabled = v.MountEnabled;
            Kit.SetLabel(_mount, v.MountText, f.State == VaultState.Mounted ? IconData.Pause : IconData.Play);
            _open.IsEnabled = v.OpenEnabled;
            Kit.SetLabel(_open, v.OpenEnabled ? $"Open {f.MountPoint}" : "Open in file manager", IconData.Folder);
            _close.IsEnabled = v.CloseEnabled;
            _rekey.IsEnabled = v.CloseEnabled; // same gate: the vault is open

            _autoMount.IsChecked = f.AutoMount;
            _autoMount.IsEnabled = v.AutoMountEnabled;
            RefreshLetters(f.ConfiguredMountPoint);
            _imagePath.Text = f.ImagePath;
            _idle.Value = Math.Clamp(f.IdleMinutes, 0, 60);
            _idleText.Text = ProtectionPresenter.IdleText(f.IdleMinutes);

            _tpmCard.IsVisible = v.TpmShown;
            _tpmAction = v.TpmAction;
            _tpmPhrase.IsVisible = v.PhraseVisible;
            _tpmPhrase.IsEnabled = v.PhraseEnabled;
            _strictRow.IsVisible = v.StrictVisible;
            Kit.SetLabel(_tpmBtn, v.TpmButtonText, IconData.Cpu);
            _tpmBtn.IsEnabled = v.TpmButtonEnabled;
            _unbind.IsVisible = v.UnbindVisible;
            _unbind.IsEnabled = v.UnbindEnabled;

            _reformat.IsEnabled = v.ReformatEnabled;
            _delete.IsEnabled = v.DeleteEnabled;
        }
        finally
        {
            _syncing = false;
        }
    }

    private void RefreshLetters(string current)
    {
        var used = DriveInfo.GetDrives()
            .Select(d => d.Name.TrimEnd('\\', '/').ToUpperInvariant())
            .ToHashSet();
        var items = new List<string>();
        for (char c = 'A'; c <= 'Z'; c++)
        {
            string l = c + ":";
            if (!used.Contains(l) || l == current)
                items.Add(l);
        }
        if (!items.Contains(current))
            items.Insert(0, current);
        if (_letter.ItemsSource is not List<string> old || !old.SequenceEqual(items))
            _letter.ItemsSource = items;
        _letter.SelectedItem = current;
    }

    // ---------------------------------------------------------- actions

    private async void CreateVault()
    {
        int size = (int)_size.Value;
        // No mount driver → the vault can't become usable — fail before an
        // image is created, not after (the banner shows the same gap).
        if (_facts?.DriverPresent == false)
        {
            Report($"Create failed — {_facts.DriverHint ?? "the Dokany driver isn't installed, so the vault couldn't mount anyway"}");
            return;
        }
        _create.IsEnabled = false;
        // Enabling is part of create: the service only consumes the verified
        // secret once VaultEnabled is on, so arm it and give the next poll a
        // moment to feed the key in before creating.
        if (_facts?.Enabled != true)
        {
            await Client.UpdateSettings(g => g.VaultEnabled = true);
            Ctx.Toast("Vault enabled — waiting for your key to feed in…", false);
            for (int i = 0; i < 12; i++)
            {
                if (await Client.Query((s, _) => s.Vault.SecretHeld))
                    break;
                await Task.Delay(500);
            }
        }
        string? err = await Client.Query<string?>((s, cfg) =>
        {
            // Re-check at engine time — the facts snapshot may be stale.
            if (!s.Vault.DriverPresent)
                return s.Vault.DriverHint ?? "the Dokany driver isn't installed — the vault can't mount without it";
            if (!s.Vault.TryCreate(size, out string e))
                return e;
            cfg.Guard.VaultSizeMb = size;
            ConfigStore.Save(cfg);
            s.MarkConfigDirty();
            return null;
        });
        Report(err is null ? null : $"Create failed — {err}", $"Vault created ({size} MB)");
        Refresh();
    }

    private async void ToggleMount()
    {
        string? err = await Client.Query<string?>((s, _) =>
        {
            VaultService v = s.Vault;
            if (v.State == VaultState.Mounted)
            {
                v.TryUnmount(out string _);
                return null;
            }
            if (v.State == VaultState.Sealed)
                return v.TryUnseal(out string ue) ? null : ue; // explicit reopen — lifts the user-seal
            return v.TryMount(out string e) ? null : e;
        });
        Report(err);
        Refresh();
    }

    private async void AcceptRollback()
    {
        string? err = await Client.Query<string?>((s, _) => s.Vault.AcceptRollback(out string e) ? null : e);
        Report(err, "Rollback accepted — vault re-opening.");
        Refresh();
    }

    private async void CloseVault()
    {
        // A real close: dismount AND drop the volume key — sealed. The latch
        // holds for the session, so auto-open can't resurrect it on the next
        // verify tick; Unseal (or a key pull/reinsert) brings it back.
        string? err = await Client.Query<string?>((s, _) => s.Vault.TrySeal(out string e) ? null : e);
        Report(err, "Vault closed — Unseal or reinsert the key to reopen.");
        Refresh();
    }

    private async void Rekey()
    {
        // Forward secrecy: every chunk + the manifest re-encrypt under a
        // fresh volume key; the vault dismounts and re-opens around the
        // file swap. Non-destructive — no hold needed.
        _rekey.IsEnabled = false;
        string? err = await Client.Query<string?>((s, _) => s.Vault.TryRekey(out string e) ? null : e);
        Report(err is null ? null : $"Rekey failed — {err}", "Vault rekeyed — volume key rotated.");
        Refresh();
    }

    private void OpenDrive()
    {
        if (_facts?.State == VaultState.Mounted)
            Ctx.Host.OpenFolder(_facts.MountPoint + Path.DirectorySeparatorChar);
    }

    private async void Reformat()
    {
        int size = (int)_size.Value;
        string? err = await Client.Query<string?>((s, _) => s.Vault.TryReformat(size, out string e) ? null : e);
        Report(err is null ? null : $"Reformat failed — {err}", "Vault reformatted — fresh image, previous contents gone.");
        Refresh();
    }

    private async void DeleteImage()
    {
        string? err = await Client.Query<string?>((s, _) => s.Vault.TryDeleteImage(out string e) ? null : e);
        Report(err is null ? null : $"Delete failed — {err}", "Vault image deleted.");
        Refresh();
    }

    /// <summary>
    /// The binding card's context action: phrase-unlock while TpmLocked,
    /// re-bind while a phrase-recovered pepper waits for a live TPM, else a
    /// fresh bind (the phrase authorizes it and seals the recovery blob).
    /// </summary>
    private async void TpmPrimary()
    {
        string phrase = _tpmPhrase.Text ?? "";
        bool strict = _strict.IsChecked == true;
        TpmAction action = _tpmAction;
        (bool ok, string msg) = await Client.Query((s, _) =>
        {
            VaultService v = s.Vault;
            string err;
            switch (action)
            {
                case TpmAction.UnlockWithPhrase:
                    return v.UnlockWithPhrase(phrase.AsSpan(), out err)
                        ? (true, "Recovery phrase accepted — vault opening. Re-bind below.")
                        : (false, err);
                case TpmAction.Rebind:
                    // Pepper already held — the phrase isn't consulted.
                    return v.BindTpm(ReadOnlySpan<char>.Empty, strict: false, out err)
                        ? (true, "Vault re-bound to this machine's TPM.")
                        : (false, err);
                case TpmAction.Bind:
                    return v.BindTpm(phrase.AsSpan(), strict, out err)
                        ? (true, strict ? "Vault bound — strict: a TPM clear means reformat."
                                        : "Vault bound to this machine (TPM).")
                        : (false, err);
                default:
                    return (false, "Nothing to do.");
            }
        });
        _tpmPhrase.Classes.Set("error", !ok);
        if (ok)
            _tpmPhrase.Text = ""; // the phrase never lingers in the field
        Ctx.Toast(msg, !ok);
        Refresh();
    }

    private async void Unbind()
    {
        string? err = await Client.Query<string?>((s, _) => s.Vault.UnbindTpm(out string e) ? null : e);
        Report(err, "Vault unbound — the image opens on any machine now.");
        Refresh();
    }

    protected override void OnHidden()
    {
        _tpmPhrase.Text = "";
        _idleSave.Stop();
    }
}
