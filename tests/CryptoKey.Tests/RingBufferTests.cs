using Xunit;

namespace CryptoKey.Tests;

/// <summary>The bounded feed buffer behind GuardService/GuardClient activity.</summary>
public class RingBufferTests
{
    [Fact]
    public void Enumeration_is_oldest_first()
    {
        var rb = new RingBuffer<int>(4);
        for (int i = 1; i <= 4; i++)
            rb.Push(i);
        Assert.Equal(new[] { 1, 2, 3, 4 }, rb.ToArray());
    }

    [Fact]
    public void Push_beyond_capacity_drops_oldest()
    {
        var rb = new RingBuffer<string>(3);
        for (int i = 1; i <= 6; i++)
            rb.Push($"line{i}");
        Assert.Equal(3, rb.Count);
        Assert.Equal(new[] { "line4", "line5", "line6" }, rb.ToArray());
    }

    [Fact]
    public void Wraps_correctly_across_many_cycles()
    {
        var rb = new RingBuffer<int>(5);
        for (int i = 0; i < 97; i++)
            rb.Push(i);
        Assert.Equal(Enumerable.Range(92, 5).ToArray(), rb.ToArray());
        Assert.Equal(92, rb[0]);
        Assert.Equal(96, rb[^1]);
    }

    [Fact]
    public void Indexer_rejects_out_of_range()
    {
        var rb = new RingBuffer<int>(4);
        rb.Push(1);
        Assert.Throws<ArgumentOutOfRangeException>(() => rb[1]);
        Assert.Throws<ArgumentOutOfRangeException>(() => rb[-1]);
    }

    [Fact]
    public void Clear_resets_and_reuses()
    {
        var rb = new RingBuffer<int>(3);
        for (int i = 0; i < 10; i++)
            rb.Push(i);
        rb.Clear();
        Assert.Empty(rb);
        rb.Push(42);
        Assert.Equal(new[] { 42 }, rb.ToArray());
    }

    [Fact]
    public void Capacity_one_is_a_single_slot()
    {
        var rb = new RingBuffer<int>(1);
        rb.Push(1);
        rb.Push(2);
        Assert.Equal(new[] { 2 }, rb.ToArray());
    }
}
