using System.Security.AccessControl;
using DokanNet;
using FileAccess = DokanNet.FileAccess;

namespace CryptoKey;

/// <summary>
/// IDokanOperations → <see cref="VaultVolume"/>. Dokan calls these from many
/// driver threads — every call funnels into the volume's internal lock.
/// Vault semantics vs. NTFS semantics: no ADS, no hardlinks, no ACLs beyond
/// a permissive default, delete-on-close via DeletePending.
/// </summary>
internal sealed class DokanVaultFileSystem : IDokanOperations
{
    private readonly VaultVolume _vol;
    private readonly Action<string>? _log;

    public DokanVaultFileSystem(VaultVolume vol, Action<string>? log = null)
    {
        _vol = vol;
        _log = log;
    }

    /// <summary>Translate vault results into NTSTATUS-ish Dokan results.</summary>
    private static NtStatus Map(VaultResult r) => r switch
    {
        VaultResult.Ok => NtStatus.Success,
        VaultResult.NotFound => NtStatus.ObjectNameNotFound,
        VaultResult.ParentMissing => NtStatus.ObjectPathNotFound,
        VaultResult.NotEmpty => NtStatus.DirectoryNotEmpty,
        VaultResult.AlreadyExists => NtStatus.ObjectNameCollision,
        VaultResult.NotADirectory => NtStatus.NotADirectory,
        VaultResult.IsADirectory => NtStatus.ObjectTypeMismatch,
        VaultResult.Full => NtStatus.DiskFull,
        VaultResult.InvalidName => NtStatus.ObjectNameInvalid,
        _ => NtStatus.Unsuccessful,
    };

    public NtStatus CreateFile(string fileName, FileAccess access, FileShare share,
        FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
    {
        try
        {
            // A CreateFile against a directory path is just an open — the
            // driver already flagged it via info.IsDirectory.
            if (info.IsDirectory)
            {
                if (!_vol.TryGet(fileName, out VaultNode? dir) || !dir.IsDir)
                    return _vol.TryGet(fileName, out _) ? NtStatus.NotADirectory
                                                        : NtStatus.ObjectPathNotFound;
                if (mode is FileMode.Create or FileMode.CreateNew or FileMode.Truncate)
                    return NtStatus.AccessDenied; // can't create-over a directory
                return NtStatus.Success;
            }

            bool exists = _vol.TryGet(fileName, out VaultNode? node);
            switch (mode)
            {
                case FileMode.Open:
                    if (!exists) return NtStatus.ObjectNameNotFound;
                    if (node!.IsDir) return NtStatus.ObjectTypeMismatch;
                    break;
                case FileMode.CreateNew:
                    if (exists) return NtStatus.ObjectNameExists;
                    goto case FileMode.Create;
                case FileMode.Create:
                    if (!exists)
                        return Map(_vol.CreateFile(fileName, out _));
                    if (node!.IsDir) return NtStatus.ObjectTypeMismatch;
                    // Create = create-or-truncate.
                    return Map(_vol.SetLength(fileName, 0));
                case FileMode.OpenOrCreate:
                    if (!exists)
                    {
                        VaultResult r = _vol.CreateFile(fileName, out _);
                        if (r != VaultResult.Ok) return Map(r);
                    }
                    break;
                case FileMode.Truncate:
                    if (!exists) return NtStatus.ObjectNameNotFound;
                    return Map(_vol.SetLength(fileName, 0));
                case FileMode.Append:
                    if (!exists)
                    {
                        VaultResult r = _vol.CreateFile(fileName, out _);
                        if (r != VaultResult.Ok) return Map(r);
                    }
                    break;
            }
            return NtStatus.Success;
        }
        catch (VaultIntegrityException ex)
        {
            _log?.Invoke($"vault integrity: {ex.Message}");
            return NtStatus.CrcError;
        }
        catch (Exception ex)
        {
            _log?.Invoke($"vault CreateFile error: {ex.Message}");
            return NtStatus.Unsuccessful;
        }
    }

    public void Cleanup(string fileName, IDokanFileInfo info)
    {
        try
        {
            // DeletePending = the last handle closed with FILE_DELETE_ON_CLOSE.
            if (info.DeletePending)
                _vol.Delete(fileName);
        }
        catch (Exception) { }
    }

    public void CloseFile(string fileName, IDokanFileInfo info)
    {
        try { _vol.Flush(); } // manifest write-through on close
        catch (Exception) { }
    }

    public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead,
        long offset, IDokanFileInfo info)
    {
        try
        {
            bytesRead = _vol.Read(fileName, offset, buffer);
            return NtStatus.Success;
        }
        catch (VaultIntegrityException ex)
        {
            _log?.Invoke($"vault integrity: {ex.Message}");
            bytesRead = 0;
            return NtStatus.CrcError;
        }
        catch (Exception)
        {
            bytesRead = 0;
            return NtStatus.Unsuccessful;
        }
    }

    public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten,
        long offset, IDokanFileInfo info)
    {
        try
        {
            if (offset < 0) // WriteToEndOfFile style
            {
                offset = _vol.TryGet(fileName, out VaultNode? n) ? n.Size : 0;
            }
            VaultResult r = _vol.Write(fileName, offset, buffer, out bytesWritten);
            return Map(r);
        }
        catch (VaultIntegrityException ex)
        {
            _log?.Invoke($"vault integrity: {ex.Message}");
            bytesWritten = 0;
            return NtStatus.CrcError;
        }
        catch (Exception)
        {
            bytesWritten = 0;
            return NtStatus.Unsuccessful;
        }
    }

    public NtStatus FlushFileBuffers(string fileName, IDokanFileInfo info)
    {
        try { _vol.Flush(); return NtStatus.Success; }
        catch (Exception) { return NtStatus.Unsuccessful; }
    }

    private static FileInformation InfoOf(VaultNode n) => new()
    {
        FileName = n.Name,
        Attributes = n.Attrs | (n.IsDir ? FileAttributes.Directory : 0),
        CreationTime = n.CreatedUtc.ToLocalTime(),
        LastAccessTime = n.AccessedUtc.ToLocalTime(),
        LastWriteTime = n.ModifiedUtc.ToLocalTime(),
        Length = n.IsDir ? 0 : n.Size,
    };

    public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo,
        IDokanFileInfo info)
    {
        fileInfo = new FileInformation();
        try
        {
            if (!_vol.TryGet(fileName, out VaultNode? node))
                return NtStatus.ObjectNameNotFound;
            fileInfo = InfoOf(node);
            return NtStatus.Success;
        }
        catch (Exception)
        {
            return NtStatus.Unsuccessful;
        }
    }

    public NtStatus FindFiles(string fileName, out IList<FileInformation> files,
        IDokanFileInfo info)
        => FindFilesWithPattern(fileName, "*", out files, info);

    public NtStatus FindFilesWithPattern(string fileName, string searchPattern,
        out IList<FileInformation> files, IDokanFileInfo info)
    {
        try
        {
            files = _vol.List(fileName)
                .Where(n => DokanHelper.DokanIsNameInExpression(
                    searchPattern, n.Name, ignoreCase: true))
                .Select(InfoOf)
                .ToList();
            return NtStatus.Success;
        }
        catch (Exception)
        {
            files = new List<FileInformation>();
            return NtStatus.Unsuccessful;
        }
    }

    public NtStatus SetFileAttributes(string fileName, FileAttributes attributes,
        IDokanFileInfo info)
    {
        try { return Map(_vol.SetAttributes(fileName, attributes)); }
        catch (Exception) { return NtStatus.Unsuccessful; }
    }

    public NtStatus SetFileTime(string fileName, DateTime? creationTime,
        DateTime? lastAccessTime, DateTime? lastWriteTime, IDokanFileInfo info)
    {
        try
        {
            return Map(_vol.SetTimes(fileName,
                creationTime?.ToUniversalTime(),
                lastAccessTime?.ToUniversalTime(),
                lastWriteTime?.ToUniversalTime()));
        }
        catch (Exception) { return NtStatus.Unsuccessful; }
    }

    public NtStatus DeleteFile(string fileName, IDokanFileInfo info)
    {
        try
        {
            if (!_vol.TryGet(fileName, out VaultNode? node))
                return NtStatus.ObjectNameNotFound;
            return node.IsDir ? NtStatus.ObjectTypeMismatch
                : Map(_vol.Delete(fileName));
        }
        catch (Exception) { return NtStatus.Unsuccessful; }
    }

    public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info)
    {
        try
        {
            if (!_vol.TryGet(fileName, out VaultNode? node))
                return NtStatus.ObjectNameNotFound;
            return !node.IsDir ? NtStatus.NotADirectory
                : Map(_vol.Delete(fileName));
        }
        catch (Exception) { return NtStatus.Unsuccessful; }
    }

    public NtStatus MoveFile(string oldName, string newName, bool replace,
        IDokanFileInfo info)
    {
        try { return Map(_vol.Move(oldName, newName, replace)); }
        catch (Exception) { return NtStatus.Unsuccessful; }
    }

    public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info)
    {
        try { return Map(_vol.SetLength(fileName, length)); }
        catch (VaultIntegrityException) { return NtStatus.CrcError; }
        catch (Exception) { return NtStatus.Unsuccessful; }
    }

    public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info)
    {
        try { return Map(_vol.SetLength(fileName, length)); }
        catch (VaultIntegrityException) { return NtStatus.CrcError; }
        catch (Exception) { return NtStatus.Unsuccessful; }
    }

    public NtStatus LockFile(string fileName, long offset, long length,
        IDokanFileInfo info) => NtStatus.Success;

    public NtStatus UnlockFile(string fileName, long offset, long length,
        IDokanFileInfo info) => NtStatus.Success;

    public NtStatus GetDiskFreeSpace(out long freeBytesAvailable,
        out long totalNumberOfBytes, out long totalNumberOfFreeBytes,
        IDokanFileInfo info)
    {
        freeBytesAvailable = totalNumberOfBytes = totalNumberOfFreeBytes = 0;
        try
        {
            (long used, long total) = _vol.GetUsage();
            totalNumberOfBytes = total;
            freeBytesAvailable = totalNumberOfFreeBytes = total - used;
            return NtStatus.Success;
        }
        catch (Exception)
        {
            return NtStatus.Unsuccessful;
        }
    }

    public NtStatus GetVolumeInformation(out string volumeLabel,
        out FileSystemFeatures features, out string fileSystemName,
        out uint maximumComponentLength, IDokanFileInfo info)
    {
        volumeLabel = "CryptoKey Vault";
        fileSystemName = "CKVAULT";
        maximumComponentLength = 255;
        // No PersistentAcls — ACLs aren't stored and SetFileSecurity refuses.
        features = FileSystemFeatures.CasePreservedNames
                 | FileSystemFeatures.UnicodeOnDisk;
        return NtStatus.Success;
    }

    public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity security,
        AccessControlSections sections, IDokanFileInfo info)
    {
        // Current-user-FullControl — the mount is the security boundary (the
        // drive only exists, session-scoped, while the key is verified), but
        // the ACL still names the owner SID rather than World so a probing
        // process sees an honest answer.
        security = new FileSecurity();
        var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User
            ?? new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.WorldSid, null);
        security.AddAccessRule(new FileSystemAccessRule(
            sid, FileSystemRights.FullControl, AccessControlType.Allow));
        return NtStatus.Success;
    }

    public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security,
        AccessControlSections sections, IDokanFileInfo info)
        => NtStatus.NotImplemented;

    public NtStatus Mounted(string mountPoint, IDokanFileInfo info)
        => NtStatus.Success;

    public NtStatus Unmounted(IDokanFileInfo info)
        => NtStatus.Success;

    public NtStatus FindStreams(string fileName, out IList<FileInformation> streams,
        IDokanFileInfo info)
    {
        streams = new List<FileInformation>();
        return NtStatus.NotImplemented; // no alternate data streams in CKVAULT1
    }
}
