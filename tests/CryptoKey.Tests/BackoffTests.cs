using Xunit;
namespace CryptoKey.Tests;

public class BackoffTests
{
    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 0)]
    [InlineData(2, 0)]
    [InlineData(3, 15)]
    [InlineData(4, 30)]
    [InlineData(5, 60)]
    [InlineData(6, 120)]
    [InlineData(7, 240)]
    [InlineData(8, 300)]
    [InlineData(10, 300)]
    [InlineData(100, 300)]
    public void Ladder_matches_spec(int fails, int expected)
        => Assert.Equal(expected, Backoff.Seconds(fails));

    [Fact]
    public void Never_exceeds_cap()
        => Assert.True(Backoff.Seconds(int.MaxValue) <= 300);
}
