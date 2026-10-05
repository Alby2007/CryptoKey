using System.Drawing.Drawing2D;

namespace CryptoKey;

internal enum ButtonVariant
{
    Secondary,  // surface fill, border — default action
    Primary,    // accent fill — the main call to action
    Danger,     // red border + red text — destructive
    Ghost,      // no fill until hover — low emphasis
}

/// <summary>Owner-drawn rounded button with animated hover/press and optional glyph.</summary>
internal sealed class AppButton : Button
{
    private ButtonVariant _variant = ButtonVariant.Secondary;
    private string? _glyph;
    private float _hover;
    private bool _pressed;

    public ButtonVariant Variant
    {
        get => _variant;
        set { _variant = value; Invalidate(); }
    }

    public string? Glyph
    {
        get => _glyph;
        set { _glyph = value; Invalidate(); }
    }

    public AppButton()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
            | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Surface;
        Font = Theme.UIFont(9f);
        Height = 32;
        TabStop = true;
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        base.OnMouseEnter(e);
        AnimateHover(1f);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        AnimateHover(0f);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button == MouseButtons.Left)
        {
            _pressed = true;
            Invalidate();
        }
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        _pressed = false;
        Invalidate();
        base.OnMouseUp(e);
    }

    protected override void OnEnabledChanged(EventArgs e)
    {
        base.OnEnabledChanged(e);
        Invalidate();
    }

    protected override void OnGotFocus(EventArgs e)
    {
        base.OnGotFocus(e);
        Invalidate();
    }

    protected override void OnLostFocus(EventArgs e)
    {
        base.OnLostFocus(e);
        Invalidate();
    }

    private void AnimateHover(float target)
    {
        if (!IsHandleCreated)
        {
            _hover = target;
            return;
        }
        float from = _hover;
        Animator.Run(140, t => { _hover = from + (target - from) * t; Invalidate(); });
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(BackColor);

        var rect = new RectangleF(0.5f, 0.5f, Width - 1f, Height - 1f);
        float h = _hover;

        Color fill, border, text;
        switch (_variant)
        {
            case ButtonVariant.Primary:
                fill = Theme.Blend(Theme.Accent, Theme.SurfaceHigh, h * 0.25f + (_pressed ? 0.15f : 0f));
                border = Theme.WithAlpha(Theme.Accent, 220);
                text = Theme.BgDeep;
                break;
            case ButtonVariant.Danger:
                fill = Theme.WithAlpha(Theme.AccentRed, (int)(18 + h * 40 + (_pressed ? 25 : 0)));
                border = Theme.WithAlpha(Theme.AccentRed, (int)(160 + h * 80));
                text = Theme.AccentRed;
                break;
            case ButtonVariant.Ghost:
                fill = Theme.WithAlpha(Theme.SurfaceHigh, (int)(h * 255 * (_pressed ? 0.7f : 1f)));
                border = Color.Transparent;
                text = Theme.Text;
                break;
            default:
                fill = Theme.Blend(Theme.Surface, Theme.SurfaceHigh, h + (_pressed ? 0.1f : 0f));
                border = Theme.Blend(Theme.Border, Theme.Accent, h * 0.6f);
                text = Theme.Text;
                break;
        }

        if (!Enabled)
        {
            fill = Theme.WithAlpha(fill, 90);
            border = Theme.WithAlpha(border, 90);
            text = Theme.WithAlpha(text, 110);
        }

        using (var path = Theme.RoundedRect(rect, Theme.RadiusSmall))
        using (var brush = new SolidBrush(fill))
            g.FillPath(brush, path);

        if (border.A > 0)
        {
            using var path = Theme.RoundedRect(rect, Theme.RadiusSmall);
            using var pen = new Pen(border, 1f);
            g.DrawPath(pen, path);
        }

        if (Focused && Enabled)
        {
            using var path = Theme.RoundedRect(
                new RectangleF(2.5f, 2.5f, Width - 5f, Height - 5f), Theme.RadiusSmall - 2);
            using var pen = new Pen(Theme.WithAlpha(Theme.Accent, 140), 1.5f);
            g.DrawPath(pen, path);
        }

        // Glyph + text, centered together.
        string label = Text;
        using var textBrush = new SolidBrush(text);
        var format = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center,
            Trimming = StringTrimming.EllipsisCharacter,
        };
        if (_glyph != null)
        {
            SizeF textSize = g.MeasureString(label, Font);
            float glyphW = 20f;
            float total = textSize.Width + glyphW;
            float x = (Width - total) / 2f;
            Theme.DrawIcon(g, _glyph, 11f, text,
                new RectangleF(x, 0, glyphW, Height));
            g.DrawString(label, Font, textBrush,
                new RectangleF(x + glyphW, 0, textSize.Width + 8f, Height), format);
        }
        else
        {
            g.DrawString(label, Font, textBrush, new RectangleF(0, 0, Width, Height), format);
        }
    }
}
