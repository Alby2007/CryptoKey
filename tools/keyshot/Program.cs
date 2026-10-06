// Renders the real CryptoKey.Win KeyArtRenderer (internal) into a PNG via
// reflection — a dev-only preview harness so lock-screen art can be
// verified without engaging an actual lock.
//   dotnet run --project tools/keyshot -- <cryptokey.dll-path> <out.png>
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Reflection;

string dllPath = args.Length > 0 ? args[0] :
    @"..\..\..\src\CryptoKey.Win\bin\Debug\net9.0-windows\cryptokey.exe";
string outPath = args.Length > 1 ? args[1] : @"C:\tmp\keyart.png";

var asm = Assembly.LoadFrom(Path.GetFullPath(dllPath));
var core = Assembly.LoadFrom(Path.Combine(
    Path.GetDirectoryName(Path.GetFullPath(dllPath))!, "CryptoKey.Core.dll"));
Type? tokens = core.GetType("CryptoKey.DesignTokens")
    ?? asm.GetType("CryptoKey.DesignTokens")
    ?? throw new Exception("DesignTokens not found");
Type? renderer = asm.GetType("CryptoKey.KeyArtRenderer")
    ?? throw new Exception("KeyArtRenderer not found");
var draw = renderer.GetMethod("Draw",
    BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
    ?? throw new Exception("Draw not found");

uint lockedArgb = (uint)(tokens.GetField("Locked")!.GetValue(null)!);
uint deepArgb = (uint)(tokens.GetField("CarbonDeep")!.GetValue(null)!);
uint carbonArgb = (uint)(tokens.GetField("Carbon")!.GetValue(null)!);
Color state = Color.FromArgb((int)lockedArgb);
Color deep = Color.FromArgb((int)deepArgb);
Color carbon = Color.FromArgb((int)carbonArgb);

// Card-sized preview on the lock floor gradient.
var bmp = new Bitmap(960, 540);
using (var g = Graphics.FromImage(bmp))
{
    g.SmoothingMode = SmoothingMode.AntiAlias;
    using (var grad = new LinearGradientBrush(
        new Rectangle(0, 0, bmp.Width, bmp.Height), deep, carbon,
        LinearGradientMode.Vertical))
        g.FillRectangle(grad, 0, 0, bmp.Width, bmp.Height);

    // eject=1 (locked), mid-breath phase.
    draw.Invoke(null, new object?[]
        { g, new RectangleF(180, 140, 600, 264), 1.0, state, 0.6f, false });
}
bmp.Save(outPath);
Console.WriteLine($"saved {outPath}");
