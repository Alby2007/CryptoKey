using System.Diagnostics;

namespace CryptoKey;

/// <summary>Recovery-phrase management, enrolled-key info, re-enroll.</summary>
internal sealed class SecurityPage : UserControl
{
    private readonly KeyConfig _config;
    private readonly GuardService _service;
    private readonly Action<string, bool> _notify;

    private readonly TextField _current;
    private readonly TextField _retype;
    private readonly Label _phrase;
    private readonly Label _result;
    private readonly Label _keyStatus;
    private readonly Label _keyDetail;
    private readonly AppButton _gen;
    private readonly AppButton _confirm;
    private readonly AppButton _repair;
    private string? _pending;   // generated phrase awaiting retype-confirmation

    public SecurityPage(KeyConfig config, GuardService service, Action<string, bool> notify)
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

        // ---- Enrolled key ----
        var keyCard = new CardPanel
        {
            Title = "Enrolled key",
            Glyph = Glyphs.Usb,
            Dock = DockStyle.Top,
            Height = 120,
            Margin = new Padding(0, 0, 0, 10),
        };
        _keyStatus = new Label
        {
            Font = Theme.UIFont(9.5f, FontStyle.Bold),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Location = new Point(16, 44),
        };
        _keyDetail = new Label
        {
            Font = Theme.MonoFont(8.5f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Location = new Point(16, 66),
        };
        var reenroll = new AppButton
        {
            Text = "Re-enroll key",
            Glyph = Glyphs.Refresh,
            Variant = ButtonVariant.Secondary,
            Location = new Point(16, 84),
            Size = new Size(140, 28),
        };
        reenroll.Click += (_, _) => ReEnroll();
        _repair = new AppButton
        {
            Text = "Repair keyfile",
            Glyph = Glyphs.Refresh,
            Variant = ButtonVariant.Secondary,
            Location = new Point(164, 84),
            Size = new Size(140, 28),
            Enabled = false,
        };
        _repair.Click += (_, _) => Repair();
        keyCard.Controls.AddRange(new Control[] { _keyStatus, _keyDetail, reenroll, _repair });

        // ---- Recovery phrase ----
        var passCard = new CardPanel
        {
            Title = "Recovery phrase",
            Glyph = Glyphs.Key,
            Dock = DockStyle.Top,
            Height = 306,
        };
        var passInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 7,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        passInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 34f));
        passInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 42f));
        passInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 40f));
        passInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 30f));
        passInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 42f));
        passInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 40f));
        passInner.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        var info = new Label
        {
            Text = "Generated, not chosen — the failsafe when your key isn't attached. " +
                   "Old passphrases no longer work: regenerate with the enrolled key attached.",
            Font = Theme.UIFont(8.5f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = false,
        };

        _current = Field("Current phrase");
        _current.EnterKey += (_, _) => GeneratePhrase();

        _gen = new AppButton
        {
            Text = "Generate new phrase",
            Glyph = Glyphs.Refresh,
            Variant = ButtonVariant.Primary,
            Dock = DockStyle.Left,
            Width = 180,
        };
        _gen.Click += (_, _) => GeneratePhrase();

        _phrase = new Label
        {
            Text = "the new phrase appears here — shown once",
            Font = Theme.MonoFont(11f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleCenter,
            AutoSize = false,
        };

        // Plain text — the phrase is already on screen, so masking the
        // retype buys nothing and only invites typos.
        _retype = Field("Retype the new phrase to confirm");
        _retype.Password = false;
        _retype.Enabled = false;
        _retype.EnterKey += (_, _) => ConfirmPhrase();

        _confirm = new AppButton
        {
            Text = "Save phrase",
            Glyph = Glyphs.Check,
            Variant = ButtonVariant.Primary,
            Dock = DockStyle.Left,
            Width = 180,
            Enabled = false,
        };
        _confirm.Click += (_, _) => ConfirmPhrase();

        _result = new Label
        {
            Font = Theme.UIFont(8.5f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
        };

        passInner.Controls.Add(info, 0, 0);
        passInner.Controls.Add(_current, 0, 1);
        passInner.Controls.Add(_gen, 0, 2);
        passInner.Controls.Add(_phrase, 0, 3);
        passInner.Controls.Add(_retype, 0, 4);
        passInner.Controls.Add(_confirm, 0, 5);
        passInner.Controls.Add(_result, 0, 6);
        passCard.Controls.Add(passInner);

        layout.Controls.Add(keyCard, 0, 0);
        layout.Controls.Add(passCard, 0, 1);
        Controls.Add(layout);

        HandleCreated += (_, _) => RefreshKeyInfo();
    }

    private static TextField Field(string placeholder)
        => new()
        {
            PlaceholderText = placeholder,
            Password = true,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 0, 0, 8),
        };

    /// <summary>
    /// Regeneration is gated two ways: the current credential, OR a freshly
    /// verified enrolled key — the key is a stronger proof than the
    /// credential anyway, and it's the migration hatch for legacy
    /// passphrases, which fail verify by design under normalization.
    /// </summary>
    private void GeneratePhrase()
    {
        if (!_gen.Enabled)
            return; // verification already in flight
        _gen.Enabled = false;
        _result.ForeColor = Theme.TextDim;
        _result.Text = "Verifying…";
        // PBKDF2 (600k) and the WMI key check would freeze the page on the
        // UI thread — run them off, finish on the pump.
        string current = _current.Text;
        Task.Run(() =>
            (current.Length > 0 && ConfigStore.VerifyPassphrase(_config, current))
            || KeyVerifiesNow())
            .ContinueWith(t => OnGenerateAuthorized(
                t.Status == TaskStatus.RanToCompletion && t.Result),
                TaskScheduler.FromCurrentSynchronizationContext());
    }

    private void OnGenerateAuthorized(bool ok)
    {
        if (IsDisposed)
            return;
        _gen.Enabled = true;
        if (!ok)
        {
            Fail("Enter the current phrase, or attach your enrolled key.", _current);
            return;
        }

        _pending = RecoveryPhrase.Generate();
        _phrase.Text = _pending;
        _phrase.ForeColor = Theme.AccentGreen;
        _retype.Enabled = true;
        _retype.ClearText();
        _retype.FocusBox();
        _confirm.Enabled = true;
        _result.ForeColor = Theme.AccentAmber;
        _result.Text = "Shown once — write it down somewhere safe, then retype it below.";
    }

    private void ConfirmPhrase()
    {
        if (_pending == null)
            return;
        Span<char> want = stackalloc char[64];
        Span<char> got = stackalloc char[64];
        try
        {
            int wantLen = RecoveryPhrase.Normalize(_pending.AsSpan(), want);
            int gotLen = RecoveryPhrase.Normalize(_retype.Text.AsSpan(), got);
            if (gotLen != wantLen || !got[..gotLen].SequenceEqual(want[..wantLen]))
            {
                Fail("That doesn't match the phrase shown — check each group.", _retype);
                return;
            }
        }
        finally
        {
            want.Clear();
            got.Clear();
        }

        ConfigStore.ChangePassphrase(_config, _pending);
        try
        {
            ConfigStore.Save(_config);
        }
        catch (Exception ex)
        {
            Fail($"Save failed: {ex.Message}", null);
            return;
        }

        // The attestation MAC covers the phrase hash — re-attest now if
        // the key is present, else the next insert self-heals via rotation.
        bool reattested;
        try
        {
            reattested = _service.RotateNow();
        }
        catch (Exception)
        {
            reattested = false;
        }
        _result.ForeColor = Theme.AccentGreen;
        _result.Text = reattested
            ? "Recovery phrase updated — key re-attested."
            : "Recovery phrase updated — key will re-attest on next insert.";
        _notify(reattested
            ? "Recovery phrase updated — key re-attested"
            : "Recovery phrase updated — key re-attests on next insert", false);

        _pending = null;
        _phrase.Text = "the new phrase appears here — shown once";
        _phrase.ForeColor = Theme.TextDim;
        _current.ClearText();
        _retype.ClearText();
        _retype.Enabled = false;
        _confirm.Enabled = false;
    }

    /// <summary>
    /// Fresh key check — the regeneration alternative to knowing the
    /// credential. Requires a Current-generation match: a stale keyfile is
    /// clone-suspect and must not authorize a credential reset (the same
    /// trust bar StrictTamper applies to unlocks).
    /// </summary>
    private bool KeyVerifiesNow()
    {
        try
        {
            UsbDisk? disk = Platform.Services.Usb.FindDisk(_config.DeviceSerial);
            return disk != null
                && KeyVerifier.Check(_config, disk).Match == SecretMatch.Current;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void Fail(string message, TextField? field)
    {
        _result.ForeColor = Theme.AccentRed;
        _result.Text = message;
        if (field != null)
        {
            field.HasError = true;
            field.TextValueChanged += ClearError;
            field.FocusBox();
        }
        _notify(message, true);

        void ClearError(object? s, EventArgs e)
        {
            field!.HasError = false;
            field.TextValueChanged -= ClearError;
        }
    }

    private void RefreshKeyInfo()
    {
        _keyStatus.Text = "Checking key…";
        _keyDetail.Text = "";
        Task.Run(() =>
        {
            string status, detail;
            bool needsRepair = false;
            try
            {
                UsbDisk? disk = Platform.Services.Usb.FindDisk(_config.DeviceSerial);
                if (disk == null)
                {
                    status = "ABSENT";
                    detail = $"serial {_config.DeviceSerial}";
                }
                else
                {
                    string vols = disk.VolumePaths.Count > 0
                        ? string.Join(", ", disk.VolumePaths)
                        : "no mounted volume";
                    bool ok = KeyVerifier.Verify(_config, disk, out string why);
                    status = $"PRESENT — {why}";
                    detail = $"{disk.Model} on {vols} — serial {_config.DeviceSerial}";
                    needsRepair = !ok;
                }
            }
            catch (Exception ex)
            {
                status = "ERROR";
                detail = ex.Message;
            }
            try
            {
                BeginInvoke(new Action(() =>
                {
                    _keyStatus.ForeColor = status.StartsWith("PRESENT")
                        ? Theme.AccentGreen : Theme.TextDim;
                    _keyStatus.Text = status;
                    _keyDetail.Text = detail;
                    _repair.Enabled = needsRepair
                        && _service.Snapshot().State != GuardState.Locked;
                }));
            }
            catch (Exception) { }
        });
    }

    private void Repair()
    {
        _repair.Enabled = false;
        bool ok;
        try { ok = _service.RepairKeyfile(); }
        catch (Exception) { ok = false; }
        _notify(ok ? "Keyfile repaired — key re-armed"
                   : "Repair failed — key absent or write error", !ok);
        RefreshKeyInfo();
    }

    private void ReEnroll()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Application.ExecutablePath, "enroll")
            {
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            _notify($"Could not launch enroll: {ex.Message}", true);
        }
    }
}
