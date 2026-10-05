namespace CryptoKey;

/// <summary>Identity, what-it-does, and the honest limitations list.</summary>
internal sealed class AboutPage : UserControl
{
    public AboutPage()
    {
        DoubleBuffered = true;
        BackColor = Theme.Bg;
        Padding = new Padding(20, 12, 20, 16);
        AutoScroll = true;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Theme.Bg,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

        // ---- Identity ----
        var idCard = new CardPanel
        {
            Dock = DockStyle.Top,
            Height = 120,
            Margin = new Padding(0, 0, 0, 10),
        };
        var brand = new Label
        {
            Text = "CryptoKey",
            Font = Theme.DisplayFont(20f, FontStyle.Bold),
            ForeColor = Theme.Text,
            AutoSize = true,
            Location = new Point(16, 20),
        };
        var tag = new Label
        {
            Text = "Turn a USB drive into a physical key for your PC. Pull it out — " +
                   "the screen locks. Put it back — you are in.",
            Font = Theme.UIFont(9f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            MaximumSize = new Size(560, 0),
            Location = new Point(16, 56),
        };
        var ver = new Label
        {
            Text = $"v{Application.ProductVersion}",
            Font = Theme.MonoFont(8f),
            ForeColor = Theme.TextDim,
            AutoSize = true,
            Location = new Point(16, 92),
        };
        idCard.Controls.AddRange(new Control[] { brand, tag, ver });

        // ---- Limitations ----
        var limCard = new CardPanel
        {
            Title = "Know the limits",
            Glyph = Glyphs.Warning,
            Dock = DockStyle.Top,
            Height = 176,
            Margin = new Padding(0, 0, 0, 10),
        };
        string[] lines =
        {
            "Ctrl+Alt+Del and the security desktop cannot be blocked.",
            "Task Manager can end the process — the lock dies with it.",
            "Elevated windows may resist the input hooks.",
            "The On-Screen Keyboard bypasses the keyboard hook if opened first.",
            "A deterrent and convenience lock — not a complete security boundary.",
        };
        var limInner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = lines.Length,
            BackColor = Theme.Surface,
            Padding = new Padding(0),
        };
        for (int i = 0; i < lines.Length; i++)
            limInner.RowStyles.Add(new RowStyle(SizeType.Percent, 100f / lines.Length));
        for (int i = 0; i < lines.Length; i++)
        {
            limInner.Controls.Add(new Label
            {
                Text = $"•  {lines[i]}",
                Font = Theme.UIFont(8.5f),
                ForeColor = i == lines.Length - 1 ? Theme.AccentAmber : Theme.TextDim,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
            }, 0, i);
        }
        limCard.Controls.Add(limInner);

        // ---- Commands ----
        var cmdCard = new CardPanel
        {
            Title = "Commands",
            Glyph = Glyphs.Info,
            Dock = DockStyle.Top,
            Height = 128,
        };
        var cmdLabel = new Label
        {
            Text = "cryptokey            launch this app\n" +
                   "cryptokey enroll     register a USB drive\n" +
                   "cryptokey lock       lock now\n" +
                   "cryptokey pause 15   pause auto-lock\n" +
                   "cryptokey resume     end a pause\n" +
                   "cryptokey status     live guard state",
            Font = Theme.MonoFont(8f),
            ForeColor = Theme.TextDim,
            Dock = DockStyle.Fill,
            Padding = new Padding(0),
        };
        cmdCard.Controls.Add(cmdLabel);

        layout.Controls.Add(idCard, 0, 0);
        layout.Controls.Add(limCard, 0, 1);
        layout.Controls.Add(cmdCard, 0, 2);
        Controls.Add(layout);
    }
}
