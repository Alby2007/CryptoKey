using Avalonia.Markup.Xaml;
using Avalonia.Styling;

namespace CryptoKey.Ui;

/// <summary>The design system's control styles (AppStyles.axaml).</summary>
internal partial class AppStyles : Styles
{
    public AppStyles() => AvaloniaXamlLoader.Load(this);
}
