# Emits current token primary group, groups, and logon SID as compact JSON (UTF-8)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class TokenSidProbe
{
    private const UInt32 TOKEN_QUERY = 0x0008;
    private const Int32 TokenGroups = 2;
    private const Int32 TokenPrimaryGroup = 5;
    private const UInt32 ERROR_INSUFFICIENT_BUFFER = 122;
    private const UInt32 SE_GROUP_LOGON_ID = 0xC0000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIMARY_GROUP
    {
        public IntPtr PrimaryGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_GROUPS
    {
        public UInt32 GroupCount;
        public SID_AND_ATTRIBUTES Groups;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        Int32 TokenInformationClass,
        IntPtr TokenInformation,
        UInt32 TokenInformationLength,
        out UInt32 ReturnLength);

    [DllImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", SetLastError = true)]
    private static extern bool ConvertSidToStringSid(IntPtr Sid, out IntPtr StringSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public sealed class TokenSids
    {
        public string primaryGroup;
        public string[] groups;
        public string logonSid;
    }

    public static TokenSids Current()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            return new TokenSids
            {
                primaryGroup = ReadPrimaryGroup(token),
                groups = ReadGroups(token, out string logonSid),
                logonSid = logonSid
            };
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static string ReadPrimaryGroup(IntPtr token)
    {
        using (TokenInformationBuffer buffer = QueryTokenInformation(token, TokenPrimaryGroup))
        {
            TOKEN_PRIMARY_GROUP primaryGroup = Marshal.PtrToStructure<TOKEN_PRIMARY_GROUP>(buffer.Pointer);
            return SidToString(primaryGroup.PrimaryGroup);
        }
    }

    private static string[] ReadGroups(IntPtr token, out string logonSid)
    {
        using (TokenInformationBuffer buffer = QueryTokenInformation(token, TokenGroups))
        {
            UInt32 count = (UInt32)Marshal.ReadInt32(buffer.Pointer);
            int offset = Marshal.OffsetOf<TOKEN_GROUPS>(nameof(TOKEN_GROUPS.Groups)).ToInt32();
            int entrySize = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
            string[] groups = new string[count];
            logonSid = null;

            for (UInt32 i = 0; i < count; i++)
            {
                IntPtr entryPtr = IntPtr.Add(buffer.Pointer, offset + ((int)i * entrySize));
                SID_AND_ATTRIBUTES entry = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(entryPtr);
                string sid = SidToString(entry.Sid);
                groups[i] = sid;

                if ((entry.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
                {
                    logonSid = sid;
                }
            }

            return groups;
        }
    }

    private static TokenInformationBuffer QueryTokenInformation(IntPtr token, Int32 tokenInformationClass)
    {
        UInt32 length;
        if (GetTokenInformation(token, tokenInformationClass, IntPtr.Zero, 0, out length))
        {
            throw new InvalidOperationException("Expected GetTokenInformation size query to fail.");
        }

        int error = Marshal.GetLastWin32Error();
        if ((UInt32)error != ERROR_INSUFFICIENT_BUFFER || length == 0)
        {
            throw new Win32Exception(error);
        }

        TokenInformationBuffer buffer = new TokenInformationBuffer(length);
        if (!GetTokenInformation(token, tokenInformationClass, buffer.Pointer, length, out length))
        {
            buffer.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return buffer;
    }

    private static string SidToString(IntPtr sid)
    {
        IntPtr stringSid;
        if (!ConvertSidToStringSid(sid, out stringSid))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            return Marshal.PtrToStringUni(stringSid);
        }
        finally
        {
            LocalFree(stringSid);
        }
    }

    private sealed class TokenInformationBuffer : IDisposable
    {
        public IntPtr Pointer { get; private set; }

        public TokenInformationBuffer(UInt32 length)
        {
            Pointer = Marshal.AllocHGlobal(checked((int)length));
        }

        public void Dispose()
        {
            if (Pointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Pointer);
                Pointer = IntPtr.Zero;
            }
        }
    }
}
'@

[TokenSidProbe]::Current() | ConvertTo-Json -Compress
