using System.Diagnostics;
using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// The Vault tab: create/seal/mount state card + settings card (auto-mount,
/// drive letter, image path, destructive ops). All reads flow from
/// <see cref="VaultService"/> state + guard snapshots; writes go through
/// the service so config and guard stay coherent.
/// </summary>
internal sealed class VaultPage : UserControl
{
    private readonly KeyConfig _config;
    private readonly GuardService _service;
    private readonly Action<string, bool> _notify;

    private readonly Badge _stateBadge;
    private readonly Label _stateText;
    private readonly Label _detailText;
    private readonly UsageBar _usage;
    private readonly Label _usageText;
    private readonly Slider _size;
    private readonly Label _sizeText;
    private readonly TableLayoutPanel _createRow;
    private readonly AppButton _createBtn;
    private readonly TableLayoutPanel _mountedRow;
    private readonly AppButton _mountBtn;
    private readonly AppButton _openBtn;
    private readonly Label _driverNote;
    private readonly ToggleSwitch _autoMount;
    private readonly Slider _idleSeal;
    private readonly Label _idleSealValue;
    private readonly System.Windows.Forms.Timer _idleSealSave = new() { Interval = 500 };
    private readonly ComboBox _letter;
    private readonly Label _imagePath;
    private readonly AppButton _reformatBtn;
    private readonly AppButton _deleteBtn;
    private AppButton? _armedBtn; // the destructively-armed button (null = none)

    public VaultPage(KeyConfig config, GuardService service, Action<string, bool> notify)
    {
        _config = config;
        _service = service;
        _notify = notify;
        DoubleBuffered = true;
        BackColor = Theme.Bg;
        Padding = new Padding(20, 12, 20, 16);
        AutoScroll = true;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Theme.Bg,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

        // ---- Card 1: vault state + controls ----
        var vaultCard = new CardPanel
        {
            Title = "Encrypted vault",
            Glyph = Glyphs.Vault,
            Dock = DockStyle.Top,
            Height = 248,
            Margin = new Padding(0, 0, 0, 10),
        };
        var vInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        vInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
        vInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 26f));
        vInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 34f));
        vInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 40f));
        vInner.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        var stateRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        stateRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120f));
        stateRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        _stateBadge = new Badge { Text = "vault", Dock = DockStyle.Left, Margin = new Padding(0, 4, 0, 0) };
        _stateText = new Label
        {
            Font = Theme.UIFont(9.5f, FontStyle.Bold),
            ForeColor = Theme.Text,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
        };
        stateRow.Controls.Add(_stateBadge, 0, 0);
        stateRow.Controls.Add(_stateText, 1, 0);
        vInner.Controls.Add(stateRow, 0, 0);

        _detailText = new Label
        {
            Font = Theme.UIFont(8.5f),
            ForeColor = Theme.TextDim,
            AutoSize = false,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        vInner.Controls.Add(_detailText, 0, 1);

        var usageRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        usageRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70f));
        usageRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30f));
        _usage = new UsageBar { Dock = DockStyle.Fill, Margin = new Padding(0, 12, 0, 0), Height = 12 };
        _usageText = new Label
        {
            Font = Theme.MonoFont(8f),
            ForeColor = Theme.TextDim,
            AutoSize = false,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        usageRow.Controls.Add(_usage, 0, 0);
        usageRow.Controls.Add(_usageText, 1, 0);
        vInner.Controls.Add(usageRow, 0, 2);

        _createRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        _createRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26f));
        _createRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46f));
        _createRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28f));
        _size = new Slider
        {
            Minimum = 64,
            Maximum = 8192,
            Step = 64,
            Value = Math.Clamp(config.Guard.VaultSizeMb, 64, 8192),
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 6, 0, 0),
        };
        _sizeText = MidLabel("");
        _size.ValueChanged += (_, _) => UpdateSizeText();
        _createBtn = new AppButton
        {
            Text = "Create vault",
            Glyph = Glyphs.Vault,
            Variant = ButtonVariant.Primary,
            Dock = DockStyle.Fill,
            Margin = new Padding(8, 2, 0, 2),
        };
        _createBtn.Click += (_, _) => CreateVault();
        _createRow.Controls.Add(_sizeText, 0, 0);
        _createRow.Controls.Add(_size, 1, 0);
        _createRow.Controls.Add(_createBtn, 2, 0);
        vInner.Controls.Add(_createRow, 0, 3);

        _mountedRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        _mountedRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        _mountedRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33f));
        _mountedRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33f));
        _mountBtn = new AppButton
        {
            Text = "Mount",
            Glyph = Glyphs.Play,
            Variant = ButtonVariant.Primary,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 4, 4, 4),
        };
        _mountBtn.Click += (_, _) => ToggleMount();
        _openBtn = new AppButton
        {
            Text = "Open in Explorer",
            Glyph = Glyphs.Folder,
            Variant = ButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 4, 4, 4),
        };
        _openBtn.Click += (_, _) => OpenExplorer();
        var closeBtn = new AppButton
        {
            Text = "Close vault",
            Glyph = Glyphs.Close,
            Variant = ButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 4, 0, 4),
        };
        closeBtn.Click += (_, _) => CloseVault();
        _mountedRow.Controls.Add(_mountBtn, 0, 0);
        _mountedRow.Controls.Add(_openBtn, 1, 0);
        _mountedRow.Controls.Add(closeBtn, 2, 0);
        vInner.Controls.Add(_mountedRow, 0, 4);

        _driverNote = new Label
        {
            Font = Theme.UIFont(8f),
            ForeColor = Theme.AccentAmber,
            AutoSize = false,
            Dock = DockStyle.Bottom,
            Height = 16,
            TextAlign = ContentAlignment.MiddleLeft,
            Cursor = Cursors.Hand,
        };
        _driverNote.Click += (_, _) =>
        {
            try { Process.Start(new ProcessStartInfo("https://dokan-dev.github.io") { UseShellExecute = true }); }
            catch (Exception) { }
        };
        vInner.Controls.Add(_driverNote, 0, 4);
        vaultCard.Controls.Add(vInner);

        // ---- Card 2: settings ----
        var setCard = new CardPanel
        {
            Title = "Vault settings",
            Glyph = Glyphs.Settings,
            Dock = DockStyle.Top,
            Height = 250,
        };
        var sInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 6,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        for (int i = 0; i < 6; i++)
            sInner.RowStyles.Add(new RowStyle(SizeType.Percent, 100f / 6f));

        _autoMount = new ToggleSwitch
        {
            Text = "Mount automatically when the key verifies",
            Checked = _config.Guard.VaultAutoMount,
            Dock = DockStyle.Fill,
        };
        _autoMount.CheckedChanged += (_, _) =>
        {
            _config.Guard.VaultAutoMount = _autoMount.Checked;
            ConfigStore.Save(_config);
            _service.MarkConfigDirty();
        };
        sInner.Controls.Add(_autoMount, 0, 0);

        var letterRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        letterRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        letterRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110f));
        letterRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 56f));
        _letter = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = Theme.SurfaceHigh,
            ForeColor = Theme.Text,
            FlatStyle = FlatStyle.Flat,
            Font = Theme.UIFont(9f),
            Dock = DockStyle.Left,
            Width = 90,
        };
        RefreshLetters();
        _letter.SelectedIndexChanged += (_, _) =>
        {
            if (_letter.SelectedItem is string letter)
            {
                _service.Vault.ApplyMountPoint(letter);
                ConfigStore.Save(_config);
                _service.MarkConfigDirty();
                _notify?.Invoke($"Vault letter → {letter} (applies on next mount)", false);
            }
        };
        letterRow.Controls.Add(MidLabel("Drive letter"), 0, 0);
        letterRow.Controls.Add(_letter, 1, 0);
        sInner.Controls.Add(letterRow, 0, 1);

        var pathRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40f));
        pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26f));
        _imagePath = new Label
        {
            Font = Theme.MonoFont(7.5f),
            ForeColor = Theme.TextDim,
            AutoSize = false,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        var openFolder = new AppButton
        {
            Text = "Open folder",
            Glyph = Glyphs.Folder,
            Variant = ButtonVariant.Ghost,
            Dock = DockStyle.Fill,
            Margin = new Padding(8, 4, 0, 4),
        };
        openFolder.Click += (_, _) =>
        {
            try
            {
                Process.Start("explorer.exe",
                    $"/select,\"{_service.Vault.ImagePath}\"");
            }
            catch (Exception) { }
        };
        pathRow.Controls.Add(MidLabel("Image file"), 0, 0);
        pathRow.Controls.Add(_imagePath, 1, 0);
        pathRow.Controls.Add(openFolder, 2, 0);
        sInner.Controls.Add(pathRow, 0, 2);

        // Idle seal — "Seal vault after idle" slider (0 = off, same call as
        // the idle lock: a surprise dismount mid-open-file is hostile UX).
        var idleSealRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        idleSealRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        idleSealRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46f));
        idleSealRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f));
        _idleSeal = new Slider
        {
            Minimum = 0,
            Maximum = 60,
            Step = 1,
            Value = Math.Clamp(_config.Guard.VaultIdleMinutes, 0, 60),
            Dock = DockStyle.Fill,
            Margin = new Padding(6, 0, 6, 0),
        };
        _idleSealValue = new Label
        {
            Text = _idleSeal.Value == 0 ? "off" : $"{_idleSeal.Value} min",
            Font = Theme.MonoFont(8.5f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleRight,
            AutoSize = false,
        };
        _idleSeal.ValueChanged += (_, _) =>
        {
            _idleSealValue.Text = _idleSeal.Value == 0 ? "off" : $"{_idleSeal.Value} min";
            _idleSealSave.Stop();
            _idleSealSave.Start(); // drags fire per-tick — debounce the write
        };
        _idleSealSave.Tick += (_, _) =>
        {
            _idleSealSave.Stop();
            _config.Guard.VaultIdleMinutes = _idleSeal.Value;
            // VaultIdleMinutes is in the attest set — toggling it is itself
            // a mild downgrade, so flag the re-attest like any covered save.
            ConfigStore.Save(_config);
            _service.MarkConfigDirty();
        };
        idleSealRow.Controls.Add(MidLabel("Seal vault after idle"), 0, 0);
        idleSealRow.Controls.Add(_idleSeal, 1, 0);
        idleSealRow.Controls.Add(_idleSealValue, 2, 0);
        sInner.Controls.Add(idleSealRow, 0, 3);

        var dangerRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
        };
        dangerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34f));
        dangerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33f));
        dangerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33f));
        _reformatBtn = new AppButton
        {
            Text = "Reformat vault",
            Glyph = Glyphs.Refresh,
            Variant = ButtonVariant.Danger,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 4, 4, 4),
        };
        _reformatBtn.Click += (_, _) => Reformat();
        _deleteBtn = new AppButton
        {
            Text = "Delete image",
            Glyph = Glyphs.Close,
            Variant = ButtonVariant.Danger,
            Dock = DockStyle.Fill,
            Margin = new Padding(4, 4, 0, 4),
        };
        _deleteBtn.Click += (_, _) => DeleteImage();
        dangerRow.Controls.Add(MidLabel("Danger zone"), 0, 0);
        dangerRow.Controls.Add(_reformatBtn, 1, 0);
        dangerRow.Controls.Add(_deleteBtn, 2, 0);
        sInner.Controls.Add(dangerRow, 0, 4);

        var vaultNote = new Label
        {
            Text = "The vault only exists while your key is in — pull the key or lock " +
                   "the session and the drive force-dismounts. Two missed secret " +
                   "rotations seal it permanently (same dead window as the keyfile).",
            Font = Theme.UIFont(8f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        sInner.Controls.Add(vaultNote, 0, 5);
        setCard.Controls.Add(sInner);

        layout.Controls.Add(vaultCard, 0, 0);
        layout.Controls.Add(setCard, 0, 1);
        Controls.Add(layout);

        UpdateSizeText();
        _service.StateChanged += OnGuardState;
        _service.Vault.StatusChanged += OnVaultState;
        Refresh();
    }

    private static Label MidLabel(string text) => new()
    {
        Text = text,
        Font = Theme.UIFont(9f),
        ForeColor = Theme.TextDim,
        AutoSize = false,
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleLeft,
    };

    private void UpdateSizeText()
    {
        int mb = _size.Value;
        _sizeText.Text = mb >= 1024 ? $"Size — {mb / 1024.0:0.#} GB" : $"Size — {mb} MB";
    }

    private void RefreshLetters()
    {
        var used = DriveInfo.GetDrives()
            .Select(d => d.Name.TrimEnd('\\').ToUpperInvariant())
            .ToHashSet();
        _letter.Items.Clear();
        for (char c = 'A'; c <= 'Z'; c++)
        {
            string letter = c + ":";
            if (!used.Contains(letter))
                _letter.Items.Add(letter);
        }
        string cur = _service.Vault.ConfiguredMountPoint;
        int idx = _letter.Items.IndexOf(cur);
        if (idx < 0)
        {
            _letter.Items.Insert(0, cur);
            idx = 0;
        }
        _letter.SelectedIndex = idx;
    }

    private void CreateVault()
    {
        // Enabling is part of create: the service only consumes the verified
        // secret once VaultEnabled is on, so a first click arms the feature and
        // the key feeds in on the next poll (~1s) — second click creates.
        if (!_config.Guard.VaultEnabled)
        {
            _config.Guard.VaultEnabled = true;
            ConfigStore.Save(_config);
            _service.MarkConfigDirty();
            _service.Vault.ReloadConfig();
            _notify?.Invoke("Vault enabled — click Create once more.", false);
            Refresh();
            return;
        }
        if (_service.Vault.TryCreate(_size.Value, out string err))
        {
            _config.Guard.VaultSizeMb = _size.Value;
            ConfigStore.Save(_config);
            _service.MarkConfigDirty();
            _notify?.Invoke($"Vault created ({_size.Value} MB)", false);
        }
        else
        {
            _notify?.Invoke($"Create failed — {err}", true);
        }
        Refresh();
    }

    private void ToggleMount()
    {
        VaultService v = _service.Vault;
        if (v.State == VaultState.RolledBack)
        {
            // Ratifying a stale image is irreversible — two-step like the
            // other destructive buttons.
            if (!ArmDestructive(_mountBtn, "Accept — click again to confirm"))
                return;
            if (v.AcceptRollback(out string aErr))
                _notify?.Invoke("Rollback accepted — vault re-opening.", false);
            else
                _notify?.Invoke(aErr, true);
            Refresh();
            return;
        }
        if (v.State == VaultState.Mounted)
        {
            v.TryUnmount(out _);
        }
        else if (!v.TryMount(out string err))
        {
            _notify?.Invoke(err, true);
        }
        Refresh();
    }

    private void CloseVault()
    {
        // Dismount only — the volume stays unsealed (volKey in memory) for an
        // instant remount; the key leaves and KeyGone drops it for real.
        VaultService v = _service.Vault;
        v.TryUnmount(out _);
        Refresh();
    }

    private void OpenExplorer()
    {
        if (_service.Vault.State == VaultState.Mounted)
        {
            try { Process.Start("explorer.exe", _service.Vault.MountPoint + "\\"); }
            catch (Exception) { }
        }
    }

    private void Reformat()
    {
        if (!ArmDestructive(_reformatBtn, "Reformat — click again to wipe"))
            return;
        if (_service.Vault.TryReformat(_size.Value, out string err))
            _notify?.Invoke("Vault reformatted — fresh image, previous contents gone.", false);
        else
            _notify?.Invoke($"Reformat failed — {err}", true);
        Refresh();
    }

    private void DeleteImage()
    {
        if (!ArmDestructive(_deleteBtn, "Delete — click again to confirm"))
            return;
        if (_service.Vault.TryDeleteImage(out string err))
            _notify?.Invoke("Vault image deleted.", false);
        else
            _notify?.Invoke($"Delete failed — {err}", true);
        Refresh();
    }

    /// <summary>
    /// Two-step destructive confirm, per button: first click arms THAT button
    /// (4s), second click on the same button executes. Clicking the other
    /// button just moves the arm — it never executes unconfirmed.
    /// </summary>
    private bool ArmDestructive(AppButton btn, string armedText)
    {
        if (_armedBtn == btn)
        {
            _armedBtn = null;
            btn.Text = _armedDefault;
            return true;
        }
        if (_armedBtn != null && !_armedBtn.IsDisposed)
            _armedBtn.Text = _armedDefault; // disarm the other button
        _armedBtn = btn;
        _armedDefault = btn.Text;
        string thisBtnDefault = _armedDefault; // per-arm snapshot — the field moves on
        btn.Text = armedText;
        var t = new System.Windows.Forms.Timer { Interval = 4000 };
        t.Tick += (_, _) =>
        {
            if (_armedBtn == btn)
                _armedBtn = null;
            if (!btn.IsDisposed) btn.Text = thisBtnDefault;
            t.Dispose();
        };
        t.Start();
        return false;
    }
    private string _armedDefault = "";

    private void OnGuardState(StatusSnapshot snap) => Post(() => Refresh());
    private void OnVaultState() => Post(() => Refresh());

    private void Post(Action work)
    {
        if (IsDisposed || !IsHandleCreated)
            return;
        try { BeginInvoke(work); }
        catch (Exception) { }
    }

    public override void Refresh()
    {
        base.Refresh();
        if (IsDisposed)
            return;
        VaultService v = _service.Vault;
        StatusSnapshot snap = _service.Snapshot();
        bool keyVerified = snap.KeyFactorArmed || v.SecretHeld;
        bool imageExists = v.ImageExists;

        _imagePath.Text = v.ImagePath;
        _driverNote.Text = v.DriverPresent ? "" : v.DriverHint ?? "";
        _driverNote.Visible = !v.DriverPresent && imageExists;

        // States, in priority order.
        if (!_config.Guard.VaultEnabled)
        {
            SetState("OFF", Theme.TextDim, "Vault disabled",
                "Enable it in config, or create below — creating arms the feature.");
            ShowCreate(keyVerified);
        }
        else if (!imageExists)
        {
            SetState("NO VAULT", Theme.TextDim, "No vault",
                "An encrypted drive that only exists while your key is present.");
            ShowCreate(keyVerified);
        }
        else if (v.State == VaultState.SealedDead)
        {
            SetState("SEALED — DEAD", Theme.AccentRed, "Permanently sealed",
                "Both key slots fell out of the rotation window — this vault cannot be " +
                "recovered. Reformat is the only path.");
            ShowMounted(false);
        }
        else if (v.State == VaultState.Corrupt)
        {
            SetState("CORRUPT", Theme.AccentRed, "Image unreadable",
                "Bad header/manifest or a read error — retries on the next verify; " +
                "reformat if it persists.");
            ShowMounted(false);
        }
        else if (v.State == VaultState.RolledBack)
        {
            SetState("ROLLED BACK", Theme.AccentRed, "Image rolled back",
                "Older than the last attested state — a rolled-back copy or a " +
                "restored backup. Accept it, or put the newer image back.");
            ShowMounted(true); // the row hosts the accept button
        }
        else if (v.State == VaultState.Mounted)
        {
            SetState("MOUNTED", Theme.AccentGreen, $"Mounted at {v.MountPoint}",
                "Writes encrypt as they land — pull the key and it force-dismounts.");
            ShowMounted(true);
        }
        else if (v.State == VaultState.Unsealed)
        {
            SetState("UNSEALED", Theme.AccentAmber, "Unsealed — not mounted",
                v.DriverPresent ? "Volume key in memory — mount to open the drive."
                                : "The Dokany driver is missing, so it can't mount yet.");
            ShowMounted(true);
        }
        else if (v.State == VaultState.NeedsDriver)
        {
            SetState("NEEDS DRIVER", Theme.AccentAmber, "Needs the Dokany driver",
                "The image is unsealed but can't mount — install Dokany, then retry.");
            ShowMounted(true);
        }
        else
        {
            // Sealed — image exists, key absent
            SetState("SEALED", Theme.TextDim, "Sealed", "Insert your key to unlock.");
            ShowMounted(false);
        }

        // Usage meter
        var usage = v.Usage;
        if (usage is (long used, long total) && v.State == VaultState.Mounted)
        {
            _usage.Fraction = total > 0 ? (double)used / total : 0;
            _usageText.Text = $"{used / (1024 * 1024)} MB / {total / (1024 * 1024)} MB";
        }
        else
        {
            _usage.Fraction = 0;
            _usageText.Text = "";
        }
        _usage.Visible = v.State == VaultState.Mounted;
        _usageText.Visible = v.State == VaultState.Mounted;

        _mountBtn.Text = v.State switch
        {
            VaultState.Mounted => "Dismount",
            VaultState.RolledBack => "Accept rolled-back state",
            _ => "Mount",
        };
        _mountBtn.Enabled = v.State is VaultState.Unsealed or VaultState.Mounted
            or VaultState.NeedsDriver or VaultState.RolledBack;
        _openBtn.Enabled = v.State == VaultState.Mounted;
        _reformatBtn.Enabled = keyVerified;
        _deleteBtn.Enabled = imageExists;
        _autoMount.Enabled = _config.Guard.VaultEnabled;
    }

    private void SetState(string badge, Color color, string status, string detail)
    {
        _stateBadge.Text = badge;
        _stateBadge.BadgeColor = color;
        _stateBadge.Size = _stateBadge.GetPreferredSize(Size.Empty);
        _stateText.Text = status;
        _detailText.Text = detail;
    }

    private void ShowCreate(bool keyVerified)
    {
        _createRow.Visible = true;
        _mountedRow.Visible = false;
        _createBtn.Enabled = keyVerified;
        _createBtn.Text = keyVerified ? "Create vault" : "Insert key to create";
        _size.Enabled = keyVerified;
    }

    private void ShowMounted(bool active)
    {
        _createRow.Visible = false;
        _mountedRow.Visible = true;
        _mountBtn.Visible = active;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _idleSealSave.Stop();
            _idleSealSave.Dispose();
            _service.StateChanged -= OnGuardState;
            _service.Vault.StatusChanged -= OnVaultState;
        }
        base.Dispose(disposing);
    }
}

/// <summary>Thin accent fill meter for vault usage.</summary>
internal sealed class UsageBar : Control
{
    private double _fraction;

    public double Fraction
    {
        get => _fraction;
        set { _fraction = Math.Clamp(value, 0, 1); Invalidate(); }
    }

    public UsageBar()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Surface;
        Height = 10;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);
        float cy = Height / 2f;
        using (var b = new SolidBrush(Theme.SurfaceHigh))
            g.FillPath(b, Theme.RoundedRect(new RectangleF(0, cy - 3, Width, 6), 3));
        if (_fraction > 0)
        {
            float w = Math.Max(6, Width * (float)_fraction);
            using var b2 = new SolidBrush(
                _fraction > 0.9 ? Theme.AccentRed : Theme.Accent);
            g.FillPath(b2, Theme.RoundedRect(new RectangleF(0, cy - 3, w, 6), 3));
        }
    }
}
