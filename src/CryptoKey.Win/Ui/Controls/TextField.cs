using System.Drawing.Drawing2D;

namespace CryptoKey;

/// <summary>
/// Rounded input: a borderless TextBox inside a styled surface with an
/// animated focus accent and an error state.
/// </summary>
internal sealed class TextField : Panel
{
    private readonly TextBox _box;
    private readonly Button _eye;
    private float _focus;
    private bool _error;
    private bool _password;

    public event EventHandler? TextValueChanged;

    public TextField()
    {
        DoubleBuffered = true;
        BackColor = Theme.Surface;
        Height = 34;
        Padding = new Padding(12, 0, 6, 0);
        TabStop = true;

        _box = new TextBox
        {
            BorderStyle = BorderStyle.None,
            BackColor = Theme.Surface,
            ForeColor = Theme.Text,
            Font = Theme.UIFont(9.5f),
            Dock = DockStyle.Fill,
        };
        _box.GotFocus += (_, _) => AnimateFocus(1f);
        _box.LostFocus += (_, _) => AnimateFocus(0f);
        _box.TextChanged += (_, _) => TextValueChanged?.Invoke(this, EventArgs.Empty);
        _box.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                EnterKey?.Invoke(this, e);
            }
        };

        _eye = new Button
        {
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Surface,
            ForeColor = Theme.TextDim,
            Width = 22,
            Dock = DockStyle.Right,
            TabStop = false,
            Cursor = Cursors.Hand,
            Visible = false,
            Margin = new Padding(0, 7, 4, 7),
        };
        _eye.FlatAppearance.BorderSize = 0;
        _eye.FlatAppearance.MouseOverBackColor = Theme.Surface;
        _eye.FlatAppearance.MouseDownBackColor = Theme.Surface;
        _eye.Font = Glyphs.Font(7.5f);
        _eye.Text = Glyphs.Eye;
        _eye.Click += (_, _) => ToggleReveal();

        Controls.Add(_box);
        Controls.Add(_eye);
    }

    public event KeyEventHandler? EnterKey;

    public new string Text
    {
        get => _box.Text;
        set => _box.Text = value;
    }

    public string PlaceholderText
    {
        get => _box.PlaceholderText;
        set => _box.PlaceholderText = value;
    }

    public bool Password
    {
        get => _password;
        set
        {
            _password = value;
            _eye.Visible = value;
            _box.UseSystemPasswordChar = value;
        }
    }

    public bool HasError
    {
        get => _error;
        set { _error = value; Invalidate(); }
    }

    public void ClearText() => _box.Clear();

    public void FocusBox() => _box.Focus();

    protected override void OnEnter(EventArgs e)
    {
        base.OnEnter(e);
        _box.Focus();
    }

    private void ToggleReveal()
    {
        _box.UseSystemPasswordChar = !_box.UseSystemPasswordChar;
        _eye.Text = _box.UseSystemPasswordChar ? Glyphs.Eye : Glyphs.EyeHide;
        _box.Focus();
        _box.SelectionStart = _box.Text.Length;
    }

    private void AnimateFocus(float target)
    {
        float from = _focus;
        Animator.Run(160, t => { _focus = from + (target - from) * t; Invalidate(); });
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);

        var rect = new RectangleF(0.5f, 0.5f, Width - 1f, Height - 1f);
        Color border = _error
            ? Theme.AccentRed
            : Theme.Blend(Theme.Border, Theme.Accent, _focus);

        using (var path = Theme.RoundedRect(rect, Theme.RadiusSmall))
        using (var brush = new SolidBrush(Theme.Surface))
            g.FillPath(brush, path);
        using (var path = Theme.RoundedRect(rect, Theme.RadiusSmall))
        using (var pen = new Pen(border, 1f + _focus))
            g.DrawPath(pen, path);
    }

    protected override void OnBackColorChanged(EventArgs e)
    {
        base.OnBackColorChanged(e);
        if (_box != null)
            _box.BackColor = _eye.BackColor = Theme.Surface;
    }
}
