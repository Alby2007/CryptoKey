using System.Diagnostics;
using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>Failsafe-passphrase management, enrolled-key info, re-enroll.</summary>
internal sealed class SecurityPage : UserControl
{
    private const int MinPassphraseLength = KeyConfig.MinPassphraseLength;

    private readonly KeyConfig _config;
    private readonly GuardService _service;
    private readonly Action<string, bool> _notify;

    private readonly TextField _current;
    private readonly TextField _newPass;
    private readonly TextField _confirm;
    private readonly StrengthMeter _meter;
    private readonly Label _result;
    private readonly Label _keyStatus;
    private readonly Label _keyDetail;
    private readonly AppButton _repair;

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

        // ---- Passphrase ----
        var passCard = new CardPanel
        {
            Title = "Failsafe passphrase",
            Glyph = Glyphs.Key,
            Dock = DockStyle.Top,
            Height = 246,
        };
        var passInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 6,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        for (int i = 0; i < 4; i++)
            passInner.RowStyles.Add(new RowStyle(SizeType.Absolute, i == 3 ? 16f : 42f));
        passInner.RowStyles.Add(new RowStyle(SizeType.Absolute, 40f));
        passInner.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        _current = Field("Current passphrase");
        _newPass = Field("New passphrase");
        _confirm = Field("Confirm new passphrase");
        _meter = new StrengthMeter { Dock = DockStyle.Fill, Margin = new Padding(2, 2, 2, 0) };
        _newPass.TextValueChanged += (_, _) => _meter.Score = Score(_newPass.Text);

        var changeBtn = new AppButton
        {
            Text = "Update passphrase",
            Glyph = Glyphs.Check,
            Variant = ButtonVariant.Primary,
            Dock = DockStyle.Left,
            Width = 180,
        };
        changeBtn.Click += (_, _) => ChangePassphrase();
        _result = new Label
        {
            Font = Theme.UIFont(8.5f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
        };

        passInner.Controls.Add(_current, 0, 0);
        passInner.Controls.Add(_newPass, 0, 1);
        passInner.Controls.Add(_confirm, 0, 2);
        passInner.Controls.Add(_meter, 0, 3);
        passInner.Controls.Add(changeBtn, 0, 4);
        passInner.Controls.Add(_result, 0, 5);
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

    private static int Score(string s)
    {
        if (s.Length == 0)
            return 0;
        int score = s.Length >= 12 ? 2 : s.Length >= 8 ? 1 : 0;
        bool lower = s.Any(char.IsLower), upper = s.Any(char.IsUpper),
             digit = s.Any(char.IsDigit), sym = s.Any(c => !char.IsLetterOrDigit(c));
        int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (sym ? 1 : 0);
        return Math.Clamp(score + (classes >= 3 ? 2 : classes >= 2 ? 1 : 0), 1, 4);
    }

    private void ChangePassphrase()
    {
        if (!ConfigStore.VerifyPassphrase(_config, _current.Text))
        {
            Fail("Current passphrase is wrong.", _current);
            return;
        }
        if (_newPass.Text.Length < MinPassphraseLength)
        {
            Fail($"New passphrase too short (min {MinPassphraseLength}).", _newPass);
            return;
        }
        if (_newPass.Text != _confirm.Text)
        {
            Fail("New passphrases do not match.", _confirm);
            return;
        }

        ConfigStore.ChangePassphrase(_config, _newPass.Text);
        try
        {
            ConfigStore.Save(_config);
        }
        catch (Exception ex)
        {
            Fail($"Save failed: {ex.Message}", null);
            return;
        }

        // The attestation MAC covers the passphrase hash — re-attest now if
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
            ? "Passphrase updated — key re-attested."
            : "Passphrase updated — key will re-attest on next insert.";
        _notify(reattested
            ? "Passphrase updated — key re-attested"
            : "Passphrase updated — key re-attests on next insert", false);
        _current.ClearText();
        _newPass.ClearText();
        _confirm.ClearText();
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
                UsbDisk? disk = UsbMonitor.FindDisk(_config.DeviceSerial);
                if (disk == null)
                {
                    status = "ABSENT";
                    detail = $"serial {_config.DeviceSerial}";
                }
                else
                {
                    string vols = disk.DriveLetters.Count > 0
                        ? string.Join(", ", disk.DriveLetters)
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

    /// <summary>Four-segment password strength bar.</summary>
    private sealed class StrengthMeter : Control
    {
        private int _score;

        public int Score
        {
            get => _score;
            set { _score = Math.Clamp(value, 0, 4); Invalidate(); }
        }

        public StrengthMeter()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
                | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            SetStyle(ControlStyles.Selectable, false);
            BackColor = Theme.Surface;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor);
            Color color = _score switch
            {
                1 => Theme.AccentRed,
                2 => Theme.AccentAmber,
                3 => Theme.AccentAmber,
                4 => Theme.AccentGreen,
                _ => Theme.TextDim,
            };
            const int segs = 4;
            float gap = 4f;
            float w = (Width - gap * (segs - 1)) / segs;
            for (int i = 0; i < segs; i++)
            {
                var r = new RectangleF(i * (w + gap), 2f, w, 5f);
                using var brush = new SolidBrush(
                    i < _score ? color : Theme.SurfaceHigh);
                g.FillPath(brush, Theme.RoundedRect(r, 2.5f));
            }
        }
    }
}
