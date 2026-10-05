using System.Media;

namespace CryptoKey;

/// <summary>
/// Audible cues — tiny PCM WAVs synthesized on the fly (on-brand: the icons
/// are rendered too, so the sounds are generated rather than shipped).
/// SoundPlayer.Play() runs on its own thread and never blocks the pump; a
/// machine with no audio path simply plays nothing. Gated on Guard.Sounds.
/// </summary>
internal static class Sounds
{
    private const int Rate = 22050;
    private const int Amp = 14000;

    /// <summary>Low thud — the lock dropping into place.</summary>
    internal static void Lock() => Play(Wav(Synth(0.18,
        t => Math.Sin(2 * Math.PI * 90 * t) * Math.Exp(-t * 22))));

    /// <summary>Short two-note chime — E5 up to A5.</summary>
    internal static void Unlock()
    {
        var s = new short[(int)(Rate * 0.30)];
        AddTone(s, 0.00, 0.09, 660);
        AddTone(s, 0.11, 0.16, 880);
        Play(Wav(s));
    }

    /// <summary>Triple square blip — harsh on purpose (tamper/storm).</summary>
    internal static void Alarm()
    {
        var s = new short[(int)(Rate * 0.42)];
        for (int i = 0; i < 3; i++)
            AddSquare(s, i * 0.14, 0.07, 920);
        Play(Wav(s));
    }

    private static void Play(byte[] wav)
    {
        try
        {
            var player = new SoundPlayer(new MemoryStream(wav, writable: false));
            player.Play(); // buffers the stream, then plays on its own thread
        }
        catch (Exception) { /* no audio device — cues are best-effort */ }
    }

    /// <summary>Render a waveform function to a 16-bit mono PCM buffer.</summary>
    private static short[] Synth(double seconds, Func<double, double> f)
    {
        var s = new short[(int)(Rate * seconds)];
        for (int i = 0; i < s.Length; i++)
            s[i] = (short)(f(i / (double)Rate) * Amp);
        return s;
    }

    /// <summary>Sine tone with attack+decay envelope, summed into the buffer.</summary>
    private static void AddTone(short[] s, double offset, double seconds, double hz)
    {
        int start = (int)(offset * Rate), n = (int)(seconds * Rate);
        for (int i = 0; i < n && start + i < s.Length; i++)
        {
            double t = i / (double)Rate;
            double env = Math.Min(1, t * 80) * Math.Exp(-t * 18);
            s[start + i] += (short)(Math.Sin(2 * Math.PI * hz * t) * env * Amp);
        }
    }

    /// <summary>Square blip — harsher than a tone, exactly what an alarm wants.</summary>
    private static void AddSquare(short[] s, double offset, double seconds, double hz)
    {
        int start = (int)(offset * Rate), n = (int)(seconds * Rate);
        for (int i = 0; i < n && start + i < s.Length; i++)
        {
            double t = i / (double)Rate;
            double env = Math.Exp(-t * 10);
            s[start + i] += (short)(Math.Sign(Math.Sin(2 * Math.PI * hz * t)) * env * (Amp / 2));
        }
    }

    /// <summary>Canonical WAV header (PCM, mono, 16-bit) + sample data.</summary>
    private static byte[] Wav(short[] pcm)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        int dataLen = pcm.Length * 2;
        w.Write("RIFF"u8);
        w.Write(36 + dataLen);
        w.Write("WAVE"u8);
        w.Write("fmt "u8);
        w.Write(16);         // fmt chunk size
        w.Write((short)1);   // PCM
        w.Write((short)1);   // mono
        w.Write(Rate);
        w.Write(Rate * 2);   // byte rate
        w.Write((short)2);   // block align
        w.Write((short)16);  // bits per sample
        w.Write("data"u8);
        w.Write(dataLen);
        foreach (short v in pcm)
            w.Write(v);
        return ms.ToArray();
    }
}
