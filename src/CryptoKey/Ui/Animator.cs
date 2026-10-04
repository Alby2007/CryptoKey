namespace CryptoKey;

/// <summary>
/// Shared easing animator: one ~60fps UI timer drives every registered
/// animation and stops when idle. When <see cref="Enabled"/> is false,
/// animations complete instantly (reduce-motion setting).
/// </summary>
internal static class Animator
{
    public static bool Enabled = true;

    private sealed class Anim
    {
        public required Func<float, float> Ease;
        public required Action<float> Step;
        public Action? Done;
        public long Start;
        public int Duration;
    }

    private static readonly List<Anim> _anims = new();
    private static System.Windows.Forms.Timer? _timer;

    public static void Run(int durationMs, Action<float> step,
        Func<float, float>? ease = null, Action? done = null)
    {
        if (!Enabled)
        {
            step(1f);
            done?.Invoke();
            return;
        }
        _anims.Add(new Anim
        {
            Ease = ease ?? EaseOutCubic,
            Step = step,
            Done = done,
            Start = Environment.TickCount64,
            Duration = Math.Max(1, durationMs),
        });
        EnsureTimer();
    }

    public static float Linear(float t) => t;
    public static float EaseOutCubic(float t) => 1f - MathF.Pow(1f - t, 3f);
    public static float EaseInOut(float t)
        => t < 0.5f ? 2f * t * t : 1f - MathF.Pow(-2f * t + 2f, 2f) / 2f;

    private static void EnsureTimer()
    {
        if (_timer == null)
        {
            _timer = new System.Windows.Forms.Timer { Interval = 15 };
            _timer.Tick += (_, _) => Tick();
        }
        if (!_timer.Enabled)
            _timer.Start();
    }

    private static void Tick()
    {
        long now = Environment.TickCount64;
        for (int i = _anims.Count - 1; i >= 0; i--)
        {
            Anim a = _anims[i];
            float t = Math.Clamp((now - a.Start) / (float)a.Duration, 0f, 1f);
            a.Step(a.Ease(t));
            if (t >= 1f)
            {
                _anims.RemoveAt(i);
                a.Done?.Invoke();
            }
        }
        if (_anims.Count == 0)
            _timer?.Stop();
    }
}
