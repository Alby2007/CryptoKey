using Xunit;

namespace CryptoKey.Ui.Tests;

/// <summary>IPC `open [page]` parsing — junk must land on Home, never on an
/// unnamed enum value.</summary>
public class RouteTests
{
    [Theory]
    [InlineData(null, "Home")]
    [InlineData("", "Home")]
    [InlineData("vault", "Vault")]
    [InlineData("VAULT", "Vault")]
    [InlineData("settings", "General")]
    [InlineData("security", "Key")]
    [InlineData("protection", "Protection")]
    [InlineData("about", "About")]
    [InlineData("garbage", "Home")]
    [InlineData("99", "Home")]  // numerics parse via Enum.TryParse — must not
    [InlineData("-1", "Home")]
    public void Parse_maps_names_and_rejects_junk(string? arg, string expected)
        => Assert.Equal(expected, Routes.Parse(arg).ToString());
}
