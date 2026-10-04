using System.Diagnostics;

namespace CryptoKey;

/// <summary>
/// Dark settings window: enrolled-key info, failsafe-passphrase change, and
/// behavior toggles. Changes save to config.json and apply live.
/// </summary>
internal sealed class SettingsForm : Form
{
    private const int MinPassphraseLength = 4;

    private readonly KeyConfig _config;
    private readonly GuardService _service;
    private readonly List<Font> _fonts = new();

    private readonly Label _keyStatus;
    private readonly Label _keyDetail;
    private readonly TextBox _currentPass;
    private readonly TextBox _newPass;
    private readonly TextBox _confirmPass;
    private readonly Label _passResult;
    private readonly Label _settingsResult;
    private readonly CheckBox _lockOnRemoval;
    private readonly CheckBox _balloonTips;
    private readonly NumericUpDown _pollMs;

    public SettingsForm(KeyConfig config, GuardService service)
    {
        _config = config;
        _service = service;

        Text = "CryptoKey Settings";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(430, 610);

        Font titleFont = MakeFont(14f, FontStyle.Bold);
        Font sectionFont = MakeFont(9f, FontStyle.Bold);

        Controls.Add(new Label
        {
            Text = "CryptoKey Settings",
            Font = titleFont,
            AutoSize = true,
            Location = new Point(14, 12),
        });

        // ---- Key ----
        Panel keyCard = Card(14, 48, 402, 116);
        keyCard.Controls.Add(SectionTitle("KEY", sectionFont, 10, 10));
        _keyStatus = new Label { AutoSize = true, Location = new Point(12, 36) };
        _keyDetail = new Label
        {
            AutoSize = true,
            ForeColor = Theme.TextDim,
            Location = new Point(12, 58),
        };
        var reenroll = new Button
        {
            Text = "Re-enroll…",
            AutoSize = true,
            Location = new Point(12, 80),
        };
        Theme.StyleButton(reenroll);
        reenroll.Click += (_, _) => ReEnroll();
        keyCard.Controls.AddRange(new Control[] { _keyStatus, _keyDetail, reenroll });
        Controls.Add(keyCard);

        // ---- Failsafe passphrase ----
        Panel secCard = Card(14, 172, 402, 208);
        secCard.Controls.Add(SectionTitle("FAILSAFE PASSPHRASE", sectionFont, 10, 10));
        _currentPass = PassBox(12, 36, "Current passphrase");
        _newPass = PassBox(12, 66, "New passphrase");
        _confirmPass = PassBox(12, 96, "Confirm new passphrase");
        var changeBtn = new Button
        {
            Text = "Change passphrase",
            AutoSize = true,
            Location = new Point(12, 130),
        };
        Theme.StyleButton(changeBtn, accent: true);
        changeBtn.Click += (_, _) => ChangePassphrase();
        _passResult = new Label { AutoSize = true, Location = new Point(12, 166) };
        secCard.Controls.AddRange(new Control[]
            { _currentPass, _newPass, _confirmPass, changeBtn, _passResult });
        Controls.Add(secCard);

        // ---- Behavior ----
        Panel behCard = Card(14, 388, 402, 138);
        behCard.Controls.Add(SectionTitle("BEHAVIOR", sectionFont, 10, 10));
        _lockOnRemoval = new CheckBox
        {
            Text = "Auto-lock when the key is removed",
            AutoSize = true,
            Location = new Point(12, 36),
            Checked = _config.Guard.LockOnRemoval,
        };
        _balloonTips = new CheckBox
        {
            Text = "Show balloon notifications on lock/unlock",
            AutoSize = true,
            Location = new Point(12, 62),
            Checked = _config.Guard.BalloonTips,
        };
        var pollLabel = new Label
        {
            Text = "USB poll interval (ms)",
            AutoSize = true,
            Location = new Point(12, 94),
        };
        _pollMs = new NumericUpDown
        {
            Location = new Point(180, 91),
            Width = 90,
            Minimum = 250,
            Maximum = 10000,
            Increment = 250,
            Value = Math.Clamp(_config.Guard.PollIntervalMs, 250, 10000),
        };
        behCard.Controls.AddRange(new Control[] { _lockOnRemoval, _balloonTips, pollLabel, _pollMs });
        Controls.Add(behCard);

        _lockOnRemoval.CheckedChanged += (_, _) => SaveSettings();
        _balloonTips.CheckedChanged += (_, _) => SaveSettings();
        _pollMs.ValueChanged += (_, _) =>
        {
            _service.ApplyPollInterval((int)_pollMs.Value);
            SaveSettings();
        };

        _settingsResult = new Label
        {
            AutoSize = true,
            ForeColor = Theme.TextDim,
            Location = new Point(14, 540),
        };
        Controls.Add(_settingsResult);

        var closeBtn = new Button
        {
            Text = "Close",
            AutoSize = true,
            Location = new Point(336, 566),
        };
        Theme.StyleButton(closeBtn);
        closeBtn.Click += (_, _) => Close();
        Controls.Add(closeBtn);

        _ = Handle; // create hwnd so DWM can restyle the title bar
        Theme.Apply(this);
        Shown += (_, _) => RefreshKeyInfo();
    }

    private Font MakeFont(float size, FontStyle style)
    {
        var f = Theme.UIFont(size, style);
        _fonts.Add(f);
        return f;
    }

    private Panel Card(int x, int y, int w, int h)
    {
        var p = Theme.Card();
        p.SetBounds(x, y, w, h);
        return p;
    }

    private static Label SectionTitle(string text, Font font, int x, int y)
        => new()
        {
            Text = text,
            Font = font,
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Location = new Point(x, y),
        };

    private static TextBox PassBox(int x, int y, string placeholder)
        => new()
        {
            Location = new Point(x, y),
            Width = 250,
            PlaceholderText = placeholder,
            UseSystemPasswordChar = true,
        };

    private void RefreshKeyInfo()
    {
        _keyStatus.Text = "Key: checking…";
        Task.Run(() =>
        {
            string status, detail;
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
                    status = ok ? "PRESENT — keyfile verified" : $"PRESENT — {why}";
                    detail = $"{disk.Model} on {vols} — serial {_config.DeviceSerial}";
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
                    _keyStatus.Text = $"Key: {status}";
                    _keyDetail.Text = detail;
                }));
            }
            catch (Exception)
            {
                // Form closed while the query was in flight.
            }
        });
    }

    private void ChangePassphrase()
    {
        if (!ConfigStore.VerifyPassphrase(_config, _currentPass.Text))
        {
            PassFail("Current passphrase is wrong.");
            return;
        }
        if (_newPass.Text.Length < MinPassphraseLength)
        {
            PassFail($"New passphrase too short (min {MinPassphraseLength}).");
            return;
        }
        if (_newPass.Text != _confirmPass.Text)
        {
            PassFail("New passphrases do not match.");
            return;
        }

        ConfigStore.ChangePassphrase(_config, _newPass.Text);
        try
        {
            ConfigStore.Save(_config);
        }
        catch (Exception ex)
        {
            PassFail($"Save failed: {ex.Message}");
            return;
        }

        _passResult.ForeColor = Theme.AccentGreen;
        _passResult.Text = "Passphrase updated.";
        _currentPass.Clear();
        _newPass.Clear();
        _confirmPass.Clear();
    }

    private void PassFail(string message)
    {
        _passResult.ForeColor = Theme.AccentRed;
        _passResult.Text = message;
    }

    private void SaveSettings()
    {
        _config.Guard.LockOnRemoval = _lockOnRemoval.Checked;
        _config.Guard.BalloonTips = _balloonTips.Checked;
        _config.Guard.PollIntervalMs = (int)_pollMs.Value;
        try
        {
            ConfigStore.Save(_config);
            _settingsResult.ForeColor = Theme.TextDim;
            _settingsResult.Text = $"Saved {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            _settingsResult.ForeColor = Theme.AccentRed;
            _settingsResult.Text = $"Save failed: {ex.Message}";
        }
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
            _keyDetail.Text = $"Could not launch enroll: {ex.Message}";
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (Font f in _fonts)
                f.Dispose();
        }
        base.Dispose(disposing);
    }
}
