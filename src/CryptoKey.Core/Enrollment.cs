namespace CryptoKey;

/// <summary>
/// `cryptokey enroll` — the console front end for <see cref="EnrollmentFlow"/>.
/// Same prompts as ever; the ordering and rollback rules live in the flow so
/// the GUI wizard can't drift from them.
/// </summary>
internal static class Enrollment
{
    public static int Run()
    {
        var flow = new EnrollmentFlow();
        if (flow.Existing?.Enrolled == true)
        {
            // An existing-but-unenrolled config is dormant, not a key to
            // overwrite — skip the confirm and just enroll.
            Console.Write($"A key is already enrolled (serial '{flow.Existing.DeviceSerial}'). Overwrite? [y/N] ");
            string? answer = Console.ReadLine()?.Trim();
            if (!string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Enrollment cancelled.");
                return 1;
            }
        }

        List<UsbDisk> disks;
        try
        {
            disks = EnrollmentFlow.ListDisks();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to enumerate USB disks: {ex.Message}");
            return 1;
        }

        if (disks.Count == 0)
        {
            Console.WriteLine("No USB disks found. Insert a flash drive and try again.");
            return 1;
        }

        Console.WriteLine("USB disks detected:");
        for (int i = 0; i < disks.Count; i++)
        {
            UsbDisk d = disks[i];
            string volumes = d.VolumePaths.Count > 0 ? string.Join(", ", d.VolumePaths) : "(no volume)";
            string serial = string.IsNullOrEmpty(d.SerialNumber) ? "(blank serial)" : d.SerialNumber;
            Console.WriteLine($"  [{i + 1}] {d.Model}  serial={serial}  volumes={volumes}");
        }

        Console.Write("Select drive number: ");
        if (!int.TryParse(Console.ReadLine(), out int pick) || pick < 1 || pick > disks.Count)
        {
            Console.WriteLine("Invalid selection.");
            return 1;
        }

        if (flow.SelectDisk(disks[pick - 1]) is string selectError)
        {
            Console.WriteLine(selectError);
            return 1;
        }
        if (flow.DiskWarning != null)
            Console.WriteLine($"WARNING: {flow.DiskWarning}");

        Console.WriteLine();
        Console.WriteLine("Your recovery phrase — the failsafe when the key isn't available:");
        Console.WriteLine();
        Console.WriteLine($"    {flow.Phrase}");
        Console.WriteLine();
        Console.WriteLine("Write it down somewhere safe — it is shown ONCE and stored only as a hash.");

        while (true)
        {
            Console.Write("Retype the phrase to confirm: ");
            ConfirmResult r = flow.Confirm((Console.ReadLine() ?? "").AsSpan());
            if (r == ConfirmResult.Match)
                break;
            if (r == ConfirmResult.Exhausted)
            {
                Console.WriteLine("Confirmation failed — enrollment aborted.");
                return 1;
            }
            Console.WriteLine("That doesn't match — check each group and try again.");
        }

        EnrollResult result = flow.Commit();
        foreach (string w in result.Warnings)
            Console.WriteLine(w);
        if (!result.Ok)
        {
            Console.WriteLine(result.Message);
            return 1;
        }
        Console.WriteLine($"{result.Message} Keyfile written to {result.KeyPath}");
        Console.WriteLine($"Config saved to {ConfigStore.ConfigPath}");
        return 0;
    }
}
