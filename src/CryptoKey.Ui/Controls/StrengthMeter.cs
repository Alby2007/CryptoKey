using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace CryptoKey.Ui;

/// <summary>
/// Four-segment password-strength meter: filled segments take the
/// Locked → Paused → Armed tone ladder by <see cref="Score"/> (0–5, same
/// scale as the caption it sits beside).
/// </summary>
internal sealed class StrengthMeter : Control
{
    public static readonly StyledProperty<int> ScoreProperty =
        AvaloniaProperty.Register<StrengthMeter, int>(nameof(Score));

    static StrengthMeter() => AffectsRender<StrengthMeter>(ScoreProperty);

    public int Score
    {
        get => GetValue(ScoreProperty);
        set => SetValue(ScoreProperty, value);
    }

    public StrengthMeter()
    {
        Width = 46;
        Height = 4;
    }

    public override void Render(DrawingContext g)
    {
        int score = Math.Clamp(Score, 0, 5);
        int filled = Math.Min(4, score);
        uint tone = score <= 1 ? DesignTokens.Locked
            : score <= 3 ? DesignTokens.Paused
            : DesignTokens.Armed;
        double gap = 3;
        double w = (Bounds.Width - 3 * gap) / 4;
        for (int i = 0; i < 4; i++)
        {
            var r = new Rect(i * (w + gap), 0, w, Bounds.Height);
            g.DrawRectangle(i < filled ? Palette.Brush(tone) : Palette.Raised,
                null, new RoundedRect(r, 2));
        }
    }
}
