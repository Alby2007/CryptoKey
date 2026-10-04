namespace CryptoKey;

/// <summary>
/// Classic lock surface: the on-desktop overlay. Composes the existing
/// <see cref="LockScreen"/> (per-monitor forms + topmost watchdog) and
/// <see cref="InputLocker"/> (low-level hooks) — identical behavior to the
/// pre-facade code.
/// </summary>
internal sealed class ClassicLockSurface : ILockSurface
{
    public event Action<string>? PassphraseSubmitted;
    public event Action? PanicRequested;

    /// <summary>Never fires — the overlay has no private desktop to flap.</summary>
    public event Action<string>? SecurityEvent
    {
        add { }
        remove { }
    }

    private readonly InputLocker _input;
    private readonly LockScreen _lock;

    public ClassicLockSurface(bool devMode)
    {
        _input = new InputLocker(devMode);
        _lock = new LockScreen();
        _input.PassphraseLengthChanged += len => _lock.SetPassphraseLength(len);
        _input.PassphraseSubmitted += s => PassphraseSubmitted?.Invoke(s);
        _input.PanicRequested += () => PanicRequested?.Invoke();
        _lock.ReassertTick += () => _input.ReassertClip();
    }

    /// <summary>Hooks + overlay. One hook retry, as before.</summary>
    public bool Engage()
    {
        bool hooked = _input.Lock() || _input.Lock();
        _lock.SetFailedAttempts(0);
        _lock.Show();
        return hooked;
    }

    /// <summary>Always succeeds — the overlay can't strand a session.</summary>
    public bool Disengage()
    {
        _input.Unlock();
        _lock.Hide();
        return true;
    }

    public void ReleaseInput() => _input.Unlock();

    public void ReassertClip() => _input.ReassertClip();

    public void SetAnimations(bool enabled) => _lock.SetAnimations(enabled);

    public void SetStatus(string message) => _lock.SetStatus(message);

    public void ResetStatus() => _lock.ResetStatus();

    public void SetPassphraseLength(int len) => _lock.SetPassphraseLength(len);

    public void SetFailedAttempts(int count) => _lock.SetFailedAttempts(count);

    public void SetCooldown(DateTime? until)
    {
        _input.SetCooldownUntil(until);
        _lock.SetCooldown(until);
    }

    public void Dispose()
    {
        _input.Dispose();
        _lock.Dispose();
    }
}
