using System.Collections;

namespace CryptoKey;

/// <summary>
/// Fixed-capacity circular buffer: <see cref="Push"/> is O(1) drop-oldest,
/// and indexer/enumeration expose items oldest-first. Backs the activity
/// feeds — the previous List+RemoveAt(0) cost an O(n) shift per log line.
/// Not thread-safe; each owner confines it to its own thread, same as the
/// List it replaces.
/// </summary>
internal sealed class RingBuffer<T> : IReadOnlyList<T>
{
    private readonly T[] _items;
    private int _head;   // slot of the oldest item once anything is buffered
    private int _count;

    public RingBuffer(int capacity)
    {
        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        _items = new T[capacity];
    }

    public int Capacity => _items.Length;

    public int Count => _count;

    public T this[int index]
    {
        get
        {
            if ((uint)index >= (uint)_count)
                throw new ArgumentOutOfRangeException(nameof(index));
            return _items[(_head + index) % _items.Length];
        }
    }

    /// <summary>Append; when full the oldest slot is overwritten.</summary>
    public void Push(T item)
    {
        if (_count == _items.Length)
        {
            _items[_head] = item;
            _head = (_head + 1) % _items.Length;
        }
        else
        {
            _items[(_head + _count) % _items.Length] = item;
            _count++;
        }
    }

    public void Clear()
    {
        Array.Clear(_items, 0, _items.Length);
        _head = 0;
        _count = 0;
    }

    public IEnumerator<T> GetEnumerator()
    {
        for (int i = 0; i < _count; i++)
            yield return _items[(_head + i) % _items.Length];
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
