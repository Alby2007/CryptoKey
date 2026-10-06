using Avalonia;
using Avalonia.Controls;
using Avalonia.Input.Platform;

namespace CryptoKey.Ui;

/// <summary>The full activity log — typed, colored, filterable, searchable.</summary>
internal sealed class ActivityPage : Page
{
    private static readonly (string Label, ActivityKind? Kind)[] Filters =
    {
        ("All", null),
        ("Security", ActivityKind.Security),
        ("Key", ActivityKind.Key),
        ("Vault", ActivityKind.Vault),
    };

    private readonly Segmented _filter;
    private readonly TextBox _search = new() { Watermark = "Search activity", Width = 260 };
    private readonly StackPanel _list = new();
    private readonly TextBlock _count = Kit.Txt("", "caption", "faint");
    private ActivityKind? _kind;
    private int _visibleCount;
    private const int MaxRows = 300;

    public ActivityPage(PageContext ctx) : base(ctx)
    {
        _filter = new Segmented(Filters.Select(f => f.Label).ToArray()) { SelectedIndex = 0, Width = 340 };
        _filter.SelectionChanged += i =>
        {
            _kind = Filters[i].Kind;
            Rebuild();
        };
        _search.TextChanged += (_, _) => Rebuild();
        _search.InnerLeftContent = new Icon(IconData.Search, 15)
        {
            Foreground = Palette.TextFaint,
            Margin = new Thickness(10, 0, 0, 0),
        };

        var toolbar = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"), ColumnSpacing = 12 };
        toolbar.Children.Add(_filter);
        Grid.SetColumn(_search, 2);
        toolbar.Children.Add(_search);

        var actions = Kit.H(8,
            Kit.Btn("Copy visible", IconData.Restore, "ghost small", CopyVisible),
            Kit.Btn("Open log folder", IconData.Folder, "ghost small", () => Ctx.Host.OpenFolder(ConfigStore.ConfigDir)));

        var card = new Border
        {
            Classes = { "card" },
            Child = Kit.V(12, toolbar, Kit.Divider(), _list, _count),
        };

        Content = Kit.PageScroll(Kit.V(16,
            Kit.PageHeader("Activity", "Everything the guard has done and seen — newest first."),
            actions, card));
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        Client.ActivityLogged += OnLine;
    }

    protected override void OnHidden() => Client.ActivityLogged -= OnLine;

    /// <summary>
    /// One new line: parse once, prepend if it passes the live filter/search,
    /// trim the tail — O(1) per log line instead of a full rebuild.
    /// </summary>
    private void OnLine(string line)
    {
        ActivityItem item = ActivityPresenter.Parse(line);
        if (ActivityPresenter.Matches(item, _kind, (_search.Text ?? "").Trim()))
        {
            if (_visibleCount == 0)
                _list.Children.Clear(); // drop the "No matching activity" row
            _list.Children.Insert(0, HomePage.FeedRow(item));
            if (_visibleCount < MaxRows)
                _visibleCount++;
            else
                _list.Children.RemoveAt(_list.Children.Count - 1);
        }
        _count.Text = $"{_visibleCount} of {Client.Activity.Count} entries";
    }

    public override void Refresh() => Rebuild();

    private List<ActivityItem> Visible()
    {
        string q = (_search.Text ?? "").Trim();
        return Client.Activity.Reverse()
            .Select(ActivityPresenter.Parse)
            .Where(i => ActivityPresenter.Matches(i, _kind, q))
            .Take(MaxRows)
            .ToList();
    }

    private void Rebuild()
    {
        _list.Children.Clear();
        List<ActivityItem> items = Visible();
        foreach (ActivityItem it in items)
            _list.Children.Add(HomePage.FeedRow(it));
        _visibleCount = items.Count;
        if (items.Count == 0)
            _list.Children.Add(Kit.Txt("No matching activity.", "caption", "dim"));
        _count.Text = $"{_visibleCount} of {Client.Activity.Count} entries";
    }

    private async void CopyVisible()
    {
        IClipboard? clip = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clip == null)
            return;
        string text = string.Join(Environment.NewLine, Visible().Select(i => $"[{i.Time}] {i.Message}"));
        await clip.SetTextAsync(text);
        Ctx.Toast("Copied to clipboard", false);
    }
}
