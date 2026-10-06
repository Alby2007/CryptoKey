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

    private void OnLine(string _) => Rebuild();

    public override void Refresh() => Rebuild();

    private List<ActivityItem> Visible()
    {
        string q = (_search.Text ?? "").Trim();
        return Client.Activity.Reverse()
            .Select(ActivityPresenter.Parse)
            .Where(i => ActivityPresenter.Matches(i, _kind, q))
            .Take(300)
            .ToList();
    }

    private void Rebuild()
    {
        _list.Children.Clear();
        List<ActivityItem> items = Visible();
        foreach (ActivityItem it in items)
            _list.Children.Add(HomePage.FeedRow(it));
        if (items.Count == 0)
            _list.Children.Add(Kit.Txt("No matching activity.", "caption", "dim"));
        _count.Text = $"{items.Count} of {Client.Activity.Count} entries";
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
