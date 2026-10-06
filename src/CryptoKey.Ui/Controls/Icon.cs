using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;

namespace CryptoKey.Ui;

/// <summary>
/// A stroked Lucide icon (24×24 design grid, 2px round strokes). Color
/// inherits the text foreground, so an icon inside a Button follows the
/// button's state colors automatically.
/// </summary>
internal sealed class Icon : Control
{
    private static readonly Dictionary<string, Geometry> Cache = new();

    public static readonly StyledProperty<string?> DataProperty =
        AvaloniaProperty.Register<Icon, string?>(nameof(Data));

    public static readonly StyledProperty<double> SizeProperty =
        AvaloniaProperty.Register<Icon, double>(nameof(Size), 18);

    public static readonly StyledProperty<double> StrokeProperty =
        AvaloniaProperty.Register<Icon, double>(nameof(Stroke), 2);

    public static readonly StyledProperty<IBrush?> ForegroundProperty =
        TextElement.ForegroundProperty.AddOwner<Icon>();

    static Icon()
    {
        AffectsRender<Icon>(DataProperty, ForegroundProperty, StrokeProperty);
        AffectsMeasure<Icon>(SizeProperty);
    }

    public Icon() { }

    public Icon(string data, double size = 18)
    {
        Data = data;
        Size = size;
    }

    public string? Data
    {
        get => GetValue(DataProperty);
        set => SetValue(DataProperty, value);
    }

    public double Size
    {
        get => GetValue(SizeProperty);
        set => SetValue(SizeProperty, value);
    }

    public double Stroke
    {
        get => GetValue(StrokeProperty);
        set => SetValue(StrokeProperty, value);
    }

    public IBrush? Foreground
    {
        get => GetValue(ForegroundProperty);
        set => SetValue(ForegroundProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize) => new(Size, Size);

    public static Geometry GeometryFor(string data)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(data, out Geometry? g))
                Cache[data] = g = Geometry.Parse(data);
            return g;
        }
    }

    public override void Render(DrawingContext context)
    {
        if (string.IsNullOrEmpty(Data))
            return;
        double s = Size / 24.0;
        var pen = new Pen(Foreground ?? Palette.Text, Stroke,
            lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
        using (context.PushTransform(Matrix.CreateScale(s, s)))
            context.DrawGeometry(null, pen, GeometryFor(Data));
    }
}
