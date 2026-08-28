using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Ports;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;

// =======================================================================================
// SECTION 1: Native Win32 Interop & P/Invoke Definitions
// =======================================================================================

public static class Win32Native
{
    // --- Kernel32 Constants ---
    public const uint PROCESS_DUP_HANDLE = 0x0040;
    public const uint DUPLICATE_SAME_ACCESS = 0x0002;
    public const uint FILE_TYPE_CHAR = 0x0002;
    public const uint FILE_NAME_NORMALIZED = 0x00000000;
    public const int OBJECT_NAME_INFORMATION = 1;
    public const uint DIGCF_PRESENT = 0x00000002;
    public const uint DIGCF_ALLCLASSES = 0x00000004;
    public const int ERROR_INSUFFICIENT_BUFFER = 122;
    public const uint DEVPROP_TYPE_STRING = 0x00000012;
    public const int ERROR_IO_PENDING = 997;

    // --- User32 MessageBox Constants ---
    public const uint MB_OK = 0x00000000;
    public const uint MB_YESNO = 0x00000004;
    public const uint MB_ICONERROR = 0x00000010;
    public const uint MB_ICONWARNING = 0x00000030;
    public const uint MB_ICONINFORMATION = 0x00000040;
    public const int IDYES = 6;
    public const int IDNO = 7;

    // --- Structs ---
    [StructLayout(LayoutKind.Sequential)]
    public struct DCB
    {
        public uint DCBlength;
        public uint BaudRate;
        public uint flags;
        public ushort wReserved;
        public ushort XonLim;
        public ushort XoffLim;
        public byte ByteSize;
        public byte Parity;
        public byte StopBits;
        public char XonChar;
        public char XoffChar;
        public char ErrorChar;
        public char EOFChar;
        public char EvtChar;
        public ushort wReserved1;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OVERLAPPED
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint Offset;
        public uint OffsetHigh;
        public IntPtr hEvent;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEVPROPKEY
    {
        public Guid fmtid;
        public uint pid;
    }

    // --- User32 P/Invoke ---
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

    // --- Kernel32 P/Invoke ---
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle,
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetFileType(IntPtr hFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFinalPathNameByHandle(
        IntPtr hFile,
        [Out] char[] lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(
        string lpDeviceName,
        [Out] char[] lpTargetPath,
        uint ucchMax);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryObject(
        IntPtr handle,
        int objectInformationClass,
        IntPtr objectInformation,
        uint objectInformationLength,
        out uint returnLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetCommState(IntPtr hFile, ref DCB lpDCB);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        ref OVERLAPPED lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetOverlappedResult(
        IntPtr hFile,
        ref OVERLAPPED lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        bool bWait);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    // --- SetupAPI P/Invoke ---
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(
        IntPtr classGuid,
        string enumerator,
        IntPtr hwndParent,
        uint flags);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiOpenDeviceInfo(
        IntPtr deviceInfoSet,
        string deviceInstanceId,
        IntPtr hwndParent,
        uint openFlags,
        ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDeviceProperty(
        IntPtr deviceInfoSet,
        ref SP_DEVINFO_DATA deviceInfoData,
        ref DEVPROPKEY propertyKey,
        out uint propertyType,
        IntPtr propertyBuffer,
        uint propertyBufferSize,
        out uint requiredSize,
        uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

}

// =======================================================================================
// SECTION 2: Protocol Specifications, Hardware Schemas & Mapping
// =======================================================================================

public static class MozaPacketSpec
{
    public const byte WriteGroup = 0x1F; // 31 Work-mode
    public const byte DeviceId   = 0x12; // 18 main device id
    public const byte CommandId  = 0x33; // 51 set-work-mode
    public const byte ReadCommandId = 0x34; // Added for status read
    public const int  MagicValue = 13;   // Checksum magic number

    public static readonly byte[] ModeOn  = new byte[] { 0x00 };
    public static readonly byte[] ModeOff = new byte[] { 0x01 };
    public static readonly byte[] ReadPayload = new byte[] { 0x00 }; // Added for status read query
}

public static class MozaVidPidMap
{
    public static readonly Dictionary<string, Type> Map = new Dictionary<string, Type>()
    {
        { "VID_346E&PID_0000", typeof(MozaPacketSpec) }, // R16, R21
        { "VID_346E&PID_0002", typeof(MozaPacketSpec) }, // R9
        { "VID_346E&PID_0004", typeof(MozaPacketSpec) }, // R5
        { "VID_346E&PID_0005", typeof(MozaPacketSpec) }, // R3
        { "VID_346E&PID_0006", typeof(MozaPacketSpec) }, // R12, R12v2
    };
}

public static class MozaVIDs
{
    // For fallback enumeration when no wheelbase PID is directly matched
    public static readonly List<string> Known = new List<string>()
    {
        "VID_346E" // Moza Racing (Gudsen)
    };
}

public static class MozaPacketBuilder
{
    public static byte CalculateChecksum(List<byte> data, int magicValue)
    {
        int sum = magicValue;
        foreach (byte b in data)
        {
            sum += b;
        }
        return (byte)(sum % 256);
    }

    public static byte[] BuildPacket(Type specType, byte[] modePayload)
    {
        return BuildPacket(specType, modePayload, false);
    }

    public static byte[] BuildPacket(Type specType, byte[] modePayload, bool isRead)
    {
        FieldInfo fWriteGroup = specType.GetField("WriteGroup", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy);
        FieldInfo fDeviceId   = specType.GetField("DeviceId", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy);
        
        string cmdField = isRead ? "ReadCommandId" : "CommandId";
        FieldInfo fCommandId  = specType.GetField(cmdField, BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy);
        
        FieldInfo fMagicValue = specType.GetField("MagicValue", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy);

        if (fWriteGroup == null || fDeviceId == null || fCommandId == null || fMagicValue == null)
        {
            throw new ArgumentException("Invalid packet spec type provided. Missing required fields.");
        }

        byte writeGroup = (byte)fWriteGroup.GetValue(null);
        byte deviceId   = (byte)fDeviceId.GetValue(null);
        byte commandId  = (byte)fCommandId.GetValue(null);
        int magicValue  = (int)fMagicValue.GetValue(null);

        byte startValue = 0x7E;
        byte messageLength = (byte)(1 + modePayload.Length);

        List<byte> packet = new List<byte>();
        packet.Add(startValue);
        packet.Add(messageLength);
        packet.Add(writeGroup);
        packet.Add(deviceId);
        packet.Add(commandId);
        packet.AddRange(modePayload);

        byte checksum = CalculateChecksum(packet, magicValue);
        packet.Add(checksum);

        return packet.ToArray();
    }
}

// =======================================================================================
// SECTION 3: Configuration & Diagnostic Logging Engine
// =======================================================================================

public class ServiceSettings
{
    public bool EnableOnStart { get; set; }
    public bool EnableOnShutdown { get; set; }
    public bool EnableSuspend { get; set; }
    public bool EnableResumeSuspend { get; set; }
    public bool EnableResumeAutomatic { get; set; }
    public bool EnableOnStop { get; set; }
    public bool EnableUpdates { get; set; }

    public ServiceSettings()
    {
        EnableOnStart = true;
        EnableOnShutdown = true;
        EnableSuspend = true;
        EnableResumeSuspend = true;
        EnableResumeAutomatic = true;
        EnableOnStop = true;
        EnableUpdates = true;
    }

    public static bool IsValid(string value)
    {
        if (value == null || value.Length != 7)
            return false;

        for (int index = 0; index < value.Length; index++)
        {
            if (value[index] != '0' && value[index] != '1')
                return false;
        }

        return true;
    }

    public static ServiceSettings Parse(string value)
    {
        ServiceSettings settings = new ServiceSettings();
        if (!IsValid(value))
            return settings;

        settings.EnableOnStart = value[0] == '1';
        settings.EnableOnShutdown = value[1] == '1';
        settings.EnableSuspend = value[2] == '1';
        settings.EnableResumeSuspend = value[3] == '1';
        settings.EnableResumeAutomatic = value[4] == '1';
        settings.EnableOnStop = value[5] == '1';
        settings.EnableUpdates = value[6] == '1';
        return settings;
    }
}

public static class Logger
{
    public static void LogConsole(string message)
    {
        Console.WriteLine(message);
    }

    public static void LogDiagnostic(string logPath, string message, bool overwrite = false)
    {
        try
        {
            using (StreamWriter sw = new StreamWriter(logPath, !overwrite))
            {
                sw.WriteLine(message);
            }
        }
        catch (Exception)
        {
        }
    }

    public static void LogEventLog(string message, EventLogEntryType type)
    {
        try
        {
            string source = "MozaPowerService";
            string logName = "Application";

            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, logName);
            }
            EventLog.WriteEntry(source, message, type);
        }
        catch (Exception)
        {
            LogConsole(string.Format("[EventLog: {0}] {1}", type.ToString(), message));
        }
    }
}

// =======================================================================================
// SECTION 4: Device Detection & Dual-Mode Transmission Engine
// =======================================================================================

public class DetectedDevice
{
    public string ComPort { get; set; }
    public string HardwareId { get; set; }
    public string DeviceName { get; set; }
    public Type TargetSpec { get; set; }
}

public static class MozaDeviceFinder
{
    private static bool IsGenericDeviceDescription(string description)
    {
        string value = description.Trim().ToUpperInvariant();
        return value == "USB SERIAL DEVICE" ||
               value == "USB COMPOSITE DEVICE" ||
               value == "COMPOSITE USB DEVICE" ||
               value == "COMMUNICATIONS PORT" ||
               value.StartsWith("USB ROOT HUB");
    }

    private static string GetDevicePropertyString(IntPtr deviceInfoSet, ref Win32Native.SP_DEVINFO_DATA deviceInfoData, ref Win32Native.DEVPROPKEY propertyKey)
    {
        uint propertyType;
        uint requiredSize;
        bool result = Win32Native.SetupDiGetDeviceProperty(
            deviceInfoSet,
            ref deviceInfoData,
            ref propertyKey,
            out propertyType,
            IntPtr.Zero,
            0,
            out requiredSize,
            0);

        if (result || Marshal.GetLastWin32Error() != Win32Native.ERROR_INSUFFICIENT_BUFFER || requiredSize == 0)
            return null;

        IntPtr propertyBuffer = Marshal.AllocHGlobal((int)requiredSize);
        try
        {
            if (!Win32Native.SetupDiGetDeviceProperty(
                deviceInfoSet,
                ref deviceInfoData,
                ref propertyKey,
                out propertyType,
                propertyBuffer,
                requiredSize,
                out requiredSize,
                0) || propertyType != Win32Native.DEVPROP_TYPE_STRING)
            {
                return null;
            }

            string description = Marshal.PtrToStringUni(propertyBuffer);
            return description == null ? null : description.TrimEnd('\0');
        }
        finally
        {
            Marshal.FreeHGlobal(propertyBuffer);
        }
    }

    private static string GetBusReportedDeviceDescription(string deviceId)
    {
        IntPtr deviceInfoSet = IntPtr.Zero;

        try
        {
            deviceInfoSet = Win32Native.SetupDiGetClassDevs(
                IntPtr.Zero,
                null,
                IntPtr.Zero,
                Win32Native.DIGCF_PRESENT | Win32Native.DIGCF_ALLCLASSES);

            if (deviceInfoSet == IntPtr.Zero || deviceInfoSet == new IntPtr(-1))
                return null;

            Win32Native.SP_DEVINFO_DATA deviceInfoData = new Win32Native.SP_DEVINFO_DATA
            {
                cbSize = Marshal.SizeOf(typeof(Win32Native.SP_DEVINFO_DATA))
            };

            if (!Win32Native.SetupDiOpenDeviceInfo(deviceInfoSet, deviceId, IntPtr.Zero, 0, ref deviceInfoData))
                return null;

            Win32Native.DEVPROPKEY propertyKey = new Win32Native.DEVPROPKEY
            {
                // DEVPKEY_Device_BusReportedDeviceDesc property key; the device ID is supplied separately below.
                fmtid = new Guid("540b947e-8b40-45bc-a8a2-6a0b894cbda2"),
                pid = 4
            };

            string deviceDescription = GetDevicePropertyString(deviceInfoSet, ref deviceInfoData, ref propertyKey);
            return string.IsNullOrEmpty(deviceDescription) || IsGenericDeviceDescription(deviceDescription) ? null : deviceDescription;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (deviceInfoSet != IntPtr.Zero && deviceInfoSet != new IntPtr(-1))
                Win32Native.SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }
    }

    public static DetectedDevice FindMozaWheelbase(bool enableDiagnostics, string logFilePath)
    {
        DetectedDevice detected = null;
        List<string> diagnosticDump = new List<string>();
        List<string> comDiagnosticDump = new List<string>();
        List<bool> comDiagnosticKnownMoza = new List<bool>();

        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%(COM%'");
            
            foreach (ManagementObject obj in searcher.Get())
            {
                string name = obj["Name"] as string;
                string deviceId = obj["DeviceID"] as string;

                if (name == null || deviceId == null)
                    continue;

                string description = obj["Description"] as string;
                string busReportedDescription = enableDiagnostics ? GetBusReportedDeviceDescription(deviceId) : null;

                string upperId = deviceId.ToUpper();
                bool isKnownMozaDevice = false;
                foreach (string vid in MozaVIDs.Known)
                {
                    if (upperId.Contains(vid.ToUpperInvariant()))
                    {
                        isKnownMozaDevice = true;
                        break;
                    }
                }
                
                if (enableDiagnostics)
                {
                    comDiagnosticDump.Add(string.Format("Found COM Device -> Name: '{0}', Bus Reported Device Description: '{1}' ({2}), WMI Description: '{3}', DeviceID: '{4}'", name, busReportedDescription ?? name, busReportedDescription == null ? "WMI Name fallback" : "SetupAPI", description ?? "(none reported)", deviceId));
                    comDiagnosticKnownMoza.Add(isKnownMozaDevice);
                }

                foreach (KeyValuePair<string, Type> mapping in MozaVidPidMap.Map)
                {
                    if (upperId.Contains(mapping.Key))
                    {
                        int idx = name.LastIndexOf("(COM");
                        if (idx >= 0)
                        {
                            string com = name.Substring(idx + 1).Replace(")", "").Trim();
                            detected = new DetectedDevice
                            {
                                ComPort = com,
                                HardwareId = deviceId,
                                DeviceName = name,
                                TargetSpec = mapping.Value
                            };
                            break;
                        }
                    }
                }

                if (detected != null)
                    break;
            }

            if (detected == null && enableDiagnostics)
            {
                bool foundAnyMozaVid = false;
                for (int index = 0; index < comDiagnosticDump.Count; index++)
                {
                    if (comDiagnosticKnownMoza[index])
                    {
                        if (!foundAnyMozaVid)
                        {
                            diagnosticDump.Add("--- KNOWN MOZA DEVICE (NO SUPPORTED WHEELBASE MATCH) ---");
                            foundAnyMozaVid = true;
                        }
                    }

                    diagnosticDump.Add(comDiagnosticDump[index]);
                }

                if (!foundAnyMozaVid)
                {
                    diagnosticDump.Add("--- NO KNOWN MOZA DEVICES FOUND ---");
                }
            }
            else if (enableDiagnostics)
            {
                diagnosticDump.AddRange(comDiagnosticDump);
            }

            if (enableDiagnostics)
            {
                if (detected != null)
                {
                    diagnosticDump.Add(string.Format("\nSupported Moza wheelbase detected -> Name: '{0}', COM Port: '{1}', DeviceID: '{2}'", detected.DeviceName, detected.ComPort, detected.HardwareId));
                }
                else
                {
                    diagnosticDump.Add("\nNo supported Moza wheelbase was detected.");
                }

                Logger.LogDiagnostic(logFilePath, "=== MozaPowerService Diagnostic Dump ===", true);
                foreach (string logLine in diagnosticDump)
                {
                    Logger.LogDiagnostic(logFilePath, logLine);
                }
                Logger.LogDiagnostic(logFilePath, "========================================");
            }
        }
        catch (Exception ex)
        {
            if (enableDiagnostics)
            {
                Logger.LogDiagnostic(logFilePath, "WMI Exception during device enumeration: " + ex.ToString(), true);
            }
        }

        return detected;
    }
}

public static class ServiceUpdater
{
    private const string RepositoryApiUrl = "https://api.github.com/repos/GitKDF/MozaPowerService/releases/latest";
    private const string ReleaseAssetName = "MozaPowerService.exe";
    private const string UpdateArgument = "--updated";
    private const string ServiceName = "MozaPowerService";

    public static System.Threading.Timer Start(string executablePath, Action requestStop)
    {
        return new System.Threading.Timer(
            state => CheckForUpdate(executablePath, requestStop),
            null,
            TimeSpan.Zero,
            TimeSpan.FromHours(24));
    }

    private static void CheckForUpdate(string executablePath, Action requestStop)
    {
        try
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            string response;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(RepositoryApiUrl);
            request.Method = "GET";
            request.UserAgent = "MozaPowerService/" + Program.Version;
            request.Timeout = 10000;

            using (WebResponse webResponse = request.GetResponse())
            using (StreamReader reader = new StreamReader(webResponse.GetResponseStream()))
            {
                response = reader.ReadToEnd();
            }

            Match tagMatch = Regex.Match(response, "\\\"tag_name\\\"\\s*:\\s*\\\"v?([0-9]+\\.[0-9]+\\.[0-9]+)\\\"", RegexOptions.IgnoreCase);
            Match assetMatch = Regex.Match(response, "\\\"browser_download_url\\\"\\s*:\\s*\\\"([^\\\"]*" + Regex.Escape(ReleaseAssetName) + ")\\\"", RegexOptions.IgnoreCase);
            if (!tagMatch.Success || !assetMatch.Success)
                return;

            Version latestVersion = new Version(tagMatch.Groups[1].Value);
            Version currentVersion = new Version(Program.Version);
            if (latestVersion <= currentVersion)
                return;

            string downloadPath = Path.Combine(Path.GetDirectoryName(executablePath), ReleaseAssetName + "." + latestVersion + ".download");
            using (WebClient client = new WebClient())
            {
                client.Headers[HttpRequestHeader.UserAgent] = "MozaPowerService/" + Program.Version;
                client.DownloadFile(assetMatch.Groups[1].Value, downloadPath);
            }

            FileInfo downloadInfo = new FileInfo(downloadPath);
            if (!downloadInfo.Exists || downloadInfo.Length == 0)
            {
                DeleteIfExists(downloadPath);
                return;
            }

            string batchPath = Path.Combine(Path.GetDirectoryName(executablePath), "MozaPowerService.update." + latestVersion + ".bat");
            WriteUpdateBatch(batchPath, downloadPath, executablePath);

            ProcessStartInfo batchStart = new ProcessStartInfo("cmd.exe", "/c \"\"" + batchPath + "\"\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                WorkingDirectory = Path.GetDirectoryName(executablePath)
            };
            Process.Start(batchStart);
            requestStop();
        }
        catch (Exception ex)
        {
            Logger.LogEventLog("Automatic update check failed: " + ex.Message, EventLogEntryType.Warning);
        }
    }

    private static void WriteUpdateBatch(string batchPath, string downloadPath, string executablePath)
    {
        using (StreamWriter writer = new StreamWriter(batchPath, false, Encoding.ASCII))
        {
            writer.WriteLine("@echo off");
            writer.WriteLine("set \"download=" + downloadPath + "\"");
            writer.WriteLine("set \"target=" + executablePath + "\"");
            writer.WriteLine(":wait");
            writer.WriteLine("sc query " + ServiceName + " | find \"STOPPED\" >nul");
            writer.WriteLine("if errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)");
            writer.WriteLine("copy /Y \"%download%\" \"%target%\" >nul");
            writer.WriteLine("del /F /Q \"%download%\" >nul 2>&1");
            writer.WriteLine("sc start " + ServiceName + " " + UpdateArgument + " >nul 2>&1");
            writer.WriteLine("del /F /Q \"%~f0\" >nul 2>&1");
        }
    }

    private static void DeleteIfExists(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch { }
    }
}

public static class PitHouseInjector
{
    public static bool IsPitHouseRunning()
    {
        Process[] procs = Process.GetProcesses();
        foreach (Process p in procs)
        {
            string pName = p.ProcessName.ToLower();
            if (pName.Contains("moza pit house") || pName.Contains("pithouse") || pName.Equals("moza"))
            {
                return true;
            }
        }

        return false;
    }

    private static string GetHandleObjectName(IntPtr handle)
    {
        IntPtr objectInfo = Marshal.AllocHGlobal(1024);
        try
        {
            uint returnLength;
            int status = Win32Native.NtQueryObject(
                handle,
                Win32Native.OBJECT_NAME_INFORMATION,
                objectInfo,
                1024,
                out returnLength);

            if (status != 0)
                return null;

            Win32Native.UNICODE_STRING objectName = (Win32Native.UNICODE_STRING)Marshal.PtrToStructure(
                objectInfo,
                typeof(Win32Native.UNICODE_STRING));
            if (objectName.Buffer == IntPtr.Zero || objectName.Length == 0)
                return null;

            return Marshal.PtrToStringUni(objectName.Buffer, objectName.Length / 2);
        }
        finally
        {
            Marshal.FreeHGlobal(objectInfo);
        }
    }

    private static string GetComPortFromHandle(IntPtr handle, string expectedComPort)
    {
        char[] pathBuffer = new char[512];
        uint pathLength = Win32Native.GetFinalPathNameByHandle(
            handle,
            pathBuffer,
            (uint)pathBuffer.Length,
            Win32Native.FILE_NAME_NORMALIZED);

        if (pathLength > 0 && pathLength < pathBuffer.Length)
        {
            string path = new string(pathBuffer, 0, (int)pathLength);
            int comIndex = path.LastIndexOf("COM", StringComparison.OrdinalIgnoreCase);
            if (comIndex >= 0)
                return path.Substring(comIndex).TrimEnd('\0');
        }

        char[] targetBuffer = new char[512];
        uint targetLength = Win32Native.QueryDosDevice(expectedComPort, targetBuffer, (uint)targetBuffer.Length);
        if (targetLength == 0)
            return null;

        string dosDeviceTarget = new string(targetBuffer, 0, (int)targetLength).TrimEnd('\0');
        string handleObjectName = GetHandleObjectName(handle);
        if (string.Equals(handleObjectName, dosDeviceTarget, StringComparison.OrdinalIgnoreCase))
            return expectedComPort;

        if (handleObjectName == null)
            return null;

        return "(unresolved: " + handleObjectName + ")";
    }

    public static bool SendViaHandleDuplication(string expectedComPort, byte[] writePayload, byte[] readPayload, bool diagnosticsOn, string logPath, out string resultDetails)
    {
        resultDetails = "Initialization failed.";
        Process targetProcess = null;
        
        Process[] procs = Process.GetProcesses();
        foreach (Process p in procs)
        {
            string pName = p.ProcessName.ToLower();
            if (pName.Contains("moza pit house") || pName.Contains("pithouse") || pName.Equals("moza"))
            {
                targetProcess = p;
                break;
            }
        }

        if (targetProcess == null)
        {
            resultDetails = "Could not find MOZA Pit House process.";
            return false;
        }

        if (diagnosticsOn)
        {
            Logger.LogDiagnostic(logPath, string.Format("Pit House handle scan: PID={0}, expected COM port={1}.", targetProcess.Id, expectedComPort));
        }

        IntPtr hProcess = Win32Native.OpenProcess(Win32Native.PROCESS_DUP_HANDLE, false, targetProcess.Id);
        if (hProcess == IntPtr.Zero)
        {
            resultDetails = string.Format("Failed to open Pit House process (PID: {0}). Error: {1}", targetProcess.Id, Marshal.GetLastWin32Error());
            return false;
        }

        bool injected = false;
        int characterHandleCount = 0;
        Win32Native.DCB dcb = new Win32Native.DCB();
        dcb.DCBlength = (uint)Marshal.SizeOf(typeof(Win32Native.DCB));

        try
        {
            for (int handleVal = 4; handleVal < 0x4000; handleVal += 4)
            {
                IntPtr hDup = IntPtr.Zero;
                if (Win32Native.DuplicateHandle(hProcess, (IntPtr)handleVal, Win32Native.GetCurrentProcess(), out hDup, 0, false, Win32Native.DUPLICATE_SAME_ACCESS))
                {
                    try
                    {
                        if (Win32Native.GetFileType(hDup) == Win32Native.FILE_TYPE_CHAR)
                        {
                            characterHandleCount++;
                            string handleComPort = GetComPortFromHandle(hDup, expectedComPort);
                            if (diagnosticsOn)
                            {
                                Logger.LogDiagnostic(logPath, string.Format(
                                    "Remote handle 0x{0:X}: character device, resolved COM port={1}, expected={2}, match={3}.",
                                    handleVal,
                                    handleComPort ?? "(unresolved)",
                                    expectedComPort,
                                    string.Equals(handleComPort, expectedComPort, StringComparison.OrdinalIgnoreCase)));
                            }
                            if (string.Equals(handleComPort, expectedComPort, StringComparison.OrdinalIgnoreCase) &&
                                Win32Native.GetCommState(hDup, ref dcb))
                            {
                                IntPtr hEvent = Win32Native.CreateEvent(IntPtr.Zero, true, false, null);
                                if (hEvent != IntPtr.Zero)
                                {
                                    try
                                    {
                                        Func<byte[], bool> writePacket = (payload) =>
                                        {
                                            Win32Native.OVERLAPPED ov = new Win32Native.OVERLAPPED();
                                            ov.hEvent = hEvent;
                                            uint written = 0;
                                            bool success = Win32Native.WriteFile(hDup, payload, (uint)payload.Length, out written, ref ov);
                                            if (!success)
                                            {
                                                int err = Marshal.GetLastWin32Error();
                                                if (err == Win32Native.ERROR_IO_PENDING)
                                                {
                                                    Win32Native.WaitForSingleObject(hEvent, 1000);
                                                    success = Win32Native.GetOverlappedResult(hDup, ref ov, out written, true);
                                                }
                                            }
                                            return success && written == (uint)payload.Length;
                                        };

                                        // 1. Send Mode Write Packet
                                        if (writePacket(writePayload))
                                        {
                                            // 2. Send Status Read Packet immediately after to sync Pit House UI
                                            if (readPayload != null)
                                            {
                                                System.Threading.Thread.Sleep(25);
                                                writePacket(readPayload);
                                            }

                                            resultDetails = string.Format("on Remote Handle 0x{0:X} for {1}.", handleVal, handleComPort);
                                            injected = true;
                                            break;
                                        }
                                    }
                                    finally
                                    {
                                        Win32Native.CloseHandle(hEvent);
                                    }
                                }
                            }
                        }
                    }
                    finally
                    {
                        Win32Native.CloseHandle(hDup);
                    }
                }
            }
        }
        finally
        {
            Win32Native.CloseHandle(hProcess);
        }

        if (!injected)
        {
            resultDetails = string.Format("Could not locate a valid, writeable handle for {0} inside Pit House process ({1} character handles inspected).", expectedComPort, characterHandleCount);
            if (diagnosticsOn)
            {
                Logger.LogDiagnostic(logPath, resultDetails);
            }
        }

        return injected;
    }
}

public static class MozaCommunicator
{
    public static bool SendCommand(bool enable, bool isManualCli, bool diagnosticsOn = false)
    {
        string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MozaPowerService.log");

        if (diagnosticsOn)
        {
            Logger.LogConsole("Diagnostic logging is ON. Scanning for devices...");
        }

        DetectedDevice device = MozaDeviceFinder.FindMozaWheelbase(diagnosticsOn, logPath);
        if (device == null)
        {
            string msg = "No supported Moza wheelbase detected.";
            if (isManualCli) Logger.LogConsole(msg);
            if (diagnosticsOn) Logger.LogConsole("Please check the generated MozaPowerService.log file.");
            return false;
        }

        if (isManualCli || diagnosticsOn)
        {
            Logger.LogConsole(string.Format("Detected: {0} on {1} ({2})", device.DeviceName, device.ComPort, device.HardwareId));
        }

        byte[] modePayload = null;
        try
        {
            FieldInfo modeField = device.TargetSpec.GetField(enable ? "ModeOn" : "ModeOff", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy);
            if (modeField != null)
            {
                modePayload = (byte[])modeField.GetValue(null);
            }
        }
        catch { }

        if (modePayload == null)
        {
            string msg = "Failed to retrieve payload mode from spec.";
            if (isManualCli) Logger.LogConsole(msg);
            Logger.LogEventLog(msg, EventLogEntryType.Error);
            return false;
        }

        // Build write packet and read query packet
        byte[] writePacket = MozaPacketBuilder.BuildPacket(device.TargetSpec, modePayload, false);
        
        byte[] readPayload = null;
        try
        {
            FieldInfo readField = device.TargetSpec.GetField("ReadPayload", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy);
            if (readField != null)
            {
                readPayload = (byte[])readField.GetValue(null);
            }
        }
        catch { }

        byte[] readPacket = readPayload != null ? MozaPacketBuilder.BuildPacket(device.TargetSpec, readPayload, true) : null;

        string packetHex = BitConverter.ToString(writePacket);
        string cmdName = enable ? "ON" : "OFF";

        if (isManualCli || diagnosticsOn)
        {
            string packetMessage = string.Format("Prepared packet ({0}): {1}", cmdName, packetHex);
            Logger.LogConsole(packetMessage);
            if (diagnosticsOn) Logger.LogDiagnostic(logPath, packetMessage);
        }

        bool success = false;
        string injectionResult = null;
        bool pitHouseRunning = false;

        try
        {
            pitHouseRunning = PitHouseInjector.IsPitHouseRunning();
        }
        catch (Exception ex)
        {
            injectionResult = "Could not check Pit House state: " + ex.Message;
        }

        if (pitHouseRunning)
        {
            if (isManualCli) Logger.LogConsole(string.Format("Pit House is running. Attempting handle duplication for {0}...", device.ComPort));

            try
            {
                success = PitHouseInjector.SendViaHandleDuplication(device.ComPort, writePacket, readPacket, diagnosticsOn, logPath, out injectionResult);
            }
            catch (Exception ex)
            {
                injectionResult = "Handle duplication error: " + ex.Message;
            }

            if (success)
            {
                string msg = string.Format("Injected COM command {0} via Pit House overlap successfully.", cmdName);
                if (isManualCli) Logger.LogConsole(msg + " " + injectionResult);
                if (diagnosticsOn) Logger.LogDiagnostic(logPath, msg + " " + injectionResult);
                Logger.LogEventLog(msg, EventLogEntryType.Information);
            }
            else
            {
                System.Threading.Thread.Sleep(50);
            }
        }

        if (!success)
        {
            if (injectionResult != null && diagnosticsOn)
            {
                Logger.LogDiagnostic(logPath, string.Format("Pit House injection failed for {0}: {1}", cmdName, injectionResult));
            }

            try
            {
                using (SerialPort port = new SerialPort(device.ComPort, 115200, Parity.None, 8, StopBits.One))
                {
                    port.ReadTimeout = 1000;
                    port.WriteTimeout = 1000;
                    port.Open();
                    port.DiscardInBuffer();
                    port.DiscardOutBuffer();
                    port.Write(writePacket, 0, writePacket.Length);
                    success = true;

                    string msg = string.Format("Direct COM command {0} sent to {1}.", cmdName, device.ComPort);
                    if (isManualCli) Logger.LogConsole(msg);
                    if (diagnosticsOn) Logger.LogDiagnostic(logPath, msg);
                    Logger.LogEventLog(msg, EventLogEntryType.Information);
                }
            }
            catch (Exception ex)
            {
                string msg = string.Format("Error sending {0} command via raw COM: {1}", cmdName, ex.Message);
                if (isManualCli) Logger.LogConsole(msg);
                if (diagnosticsOn) Logger.LogDiagnostic(logPath, msg);
                Logger.LogEventLog(msg, EventLogEntryType.Warning);
            }
        }

        if (diagnosticsOn)
        {
            Logger.LogDiagnostic(logPath, success ? "Command completed successfully." : "Command failed.");
        }

        return success;
    }
}

// =======================================================================================
// SECTION 5: Windows Service Lifecycle Handler
// =======================================================================================

public class MozaPowerService : ServiceBase
{
    private ServiceSettings _settings;
    private System.Threading.Timer _updateTimer;
    private volatile bool _updateInProgress;

    public MozaPowerService()
    {
        this.ServiceName = "MozaPowerService";
        this.CanHandlePowerEvent = true;
        this.CanShutdown = true;
        this.CanStop = true;
    }

    protected override void OnStart(string[] args)
    {
            try
            {
                bool isUpdateRestart = false;
                string settingsArgument = Program.InstalledSettingsArgument;
                if (args != null)
                {
                    foreach (string argument in args)
                    {
                        if (string.Equals(argument, "--updated", StringComparison.OrdinalIgnoreCase))
                        {
                            isUpdateRestart = true;
                        }
                    }
                }

                _settings = ServiceSettings.Parse(settingsArgument);

                if (_settings.EnableOnStart && !isUpdateRestart)
                {
                    Logger.LogEventLog("Service started. EnableOnStart is TRUE. Sending ON command.", EventLogEntryType.Information);
                    MozaCommunicator.SendCommand(true, false);
                }
                else if (!isUpdateRestart)
                {
                    Logger.LogEventLog("Service started. EnableOnStart is FALSE. Skipping ON command.", EventLogEntryType.Information);
                }

                if (isUpdateRestart)
                {
                    Logger.LogEventLog("Service restarted after an automatic update. Skipping startup ON command.", EventLogEntryType.Information);
                }

                if (_settings.EnableUpdates)
                {
                    _updateTimer = ServiceUpdater.Start(Assembly.GetExecutingAssembly().Location, RequestUpdateStop);
                }
        }
        catch (Exception ex)
        {
            Logger.LogEventLog("Error in OnStart: " + ex.Message, EventLogEntryType.Error);
        }
    }

    protected override void OnStop()
    {
        try
        {
            if (_updateTimer != null)
            {
                _updateTimer.Dispose();
                _updateTimer = null;
            }

            ServiceSettings settings = _settings ?? new ServiceSettings();
            if (settings.EnableOnStop && !_updateInProgress)
            {
                Logger.LogEventLog("Service stopping. EnableOnStop is TRUE. Sending OFF command as a shutdown fallback.", EventLogEntryType.Information);
                MozaCommunicator.SendCommand(false, false);
            }
            else if (_updateInProgress)
            {
                Logger.LogEventLog("Service stopping for an automatic update. Skipping OFF command.", EventLogEntryType.Information);
            }
            else
            {
                Logger.LogEventLog("Service stopping. EnableOnStop is FALSE. Skipping OFF command.", EventLogEntryType.Information);
            }
        }
        catch (Exception ex)
        {
            Logger.LogEventLog("Error in OnStop: " + ex.Message, EventLogEntryType.Error);
        }
    }

    private void RequestUpdateStop()
    {
        _updateInProgress = true;
        try
        {
            ProcessStartInfo stopInfo = new ProcessStartInfo("sc.exe", "stop MozaPowerService")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            };
            Process.Start(stopInfo);
        }
        catch (Exception ex)
        {
            _updateInProgress = false;
            Logger.LogEventLog("Automatic update could not stop the service: " + ex.Message, EventLogEntryType.Warning);
        }
    }

    protected override void OnShutdown()
    {
        try
        {
            ServiceSettings settings = _settings ?? new ServiceSettings();
            if (settings.EnableOnShutdown)
            {
                Logger.LogEventLog("System shutting down. EnableOnShutdown is TRUE. Sending OFF command.", EventLogEntryType.Information);
                MozaCommunicator.SendCommand(false, false);
            }
        }
        catch (Exception ex)
        {
            Logger.LogEventLog("Error in OnShutdown: " + ex.Message, EventLogEntryType.Error);
        }
    }

    protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
    {
        try
        {
            ServiceSettings settings = _settings ?? new ServiceSettings();

            switch (powerStatus)
            {
                case PowerBroadcastStatus.Suspend:
                    if (settings.EnableSuspend)
                    {
                        Logger.LogEventLog("System suspending. EnableSuspend is TRUE. Sending OFF command.", EventLogEntryType.Information);
                        MozaCommunicator.SendCommand(false, false);
                    }
                    break;

                case PowerBroadcastStatus.ResumeSuspend:
                    if (settings.EnableResumeSuspend)
                    {
                        Logger.LogEventLog("System resuming (User Initiated). EnableResumeSuspend is TRUE. Sending ON command.", EventLogEntryType.Information);
                        MozaCommunicator.SendCommand(true, false);
                    }
                    break;

                case PowerBroadcastStatus.ResumeAutomatic:
                    if (settings.EnableResumeAutomatic)
                    {
                        Logger.LogEventLog("System resuming (Automatic/Wake Timer). EnableResumeAutomatic is TRUE. Sending ON command.", EventLogEntryType.Information);
                        MozaCommunicator.SendCommand(true, false);
                    }
                    break;
            }

            return true;
        }
        catch (Exception ex)
        {
            Logger.LogEventLog("Error in OnPowerEvent: " + ex.Message, EventLogEntryType.Error);
        }

        return false;
    }
}

// =======================================================================================
// SECTION 6: Service Management & Self-Installation Engine
// =======================================================================================

public static class ServiceInstallerUtil
{
    private const string ServiceName = "MozaPowerService";

    public static bool IsServiceInstalled()
    {
        try
        {
            foreach (ServiceController sc in ServiceController.GetServices())
            {
                if (sc.ServiceName.Equals(ServiceName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    public static void Install(string settingsArgument)
    {
        try
        {
            string exePath = Assembly.GetExecutingAssembly().Location;
            string originalExePath = exePath;

            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string recommendedDir = Path.Combine(programFiles, "MozaPowerService");
            string recommendedExePath = Path.Combine(recommendedDir, Path.GetFileName(exePath));

            Console.WriteLine("Starting " + ServiceName + " Installation...");
            Console.WriteLine();

            if (!string.Equals(Path.GetFullPath(exePath), Path.GetFullPath(recommendedExePath), StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("This application will be copied to: " + recommendedExePath);
                Console.WriteLine("The Windows service will be installed and started.");
                Console.WriteLine("To uninstall later, run \"MozaPowerService uninstall\" from that location.");
            }
            else
            {
                Console.WriteLine("The application is already in the recommended installation path.");
                Console.WriteLine("The Windows service will be installed and started.");
                Console.WriteLine("To uninstall later, run \"MozaPowerService uninstall\" from that location.");
            }

            if (!ConsoleUtil.PromptYesNo("\nProceed with installation? (Y/N): "))
            {
                Console.WriteLine("Installation cancelled.");
                return;
            }

            if (!string.Equals(Path.GetFullPath(exePath), Path.GetFullPath(recommendedExePath), StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    if (!Directory.Exists(recommendedDir)) Directory.CreateDirectory(recommendedDir);
                    File.Copy(exePath, recommendedExePath, true);
                    exePath = recommendedExePath;
                    Console.WriteLine("Copied executable to " + recommendedExePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to copy executable to the recommended path: " + ex.Message);
                    Console.WriteLine("Installation cancelled.");
                    return;
                }
            }

            string serviceBinPath = string.Format("\\\"{0}\\\"", exePath);
            if (!string.IsNullOrEmpty(settingsArgument))
            {
                serviceBinPath += " " + settingsArgument;
            }

            ProcessStartInfo psiCreate = new ProcessStartInfo("sc.exe", string.Format("create {0} binPath= \"{1}\" start= auto", ServiceName, serviceBinPath))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };

            using (Process p = Process.Start(psiCreate))
            {
                p.WaitForExit();
                Console.WriteLine(p.StandardOutput.ReadToEnd().Trim());
            }

            Console.WriteLine("Setting service description...");
            ProcessStartInfo psiDesc = new ProcessStartInfo("sc.exe", string.Format("description {0} \"Manages power states for Moza Racing wheelbases during system events (Start, Shutdown, Sleep).\"", ServiceName))
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (Process pDesc = Process.Start(psiDesc)) 
            {
                pDesc.WaitForExit();
            }

            Console.WriteLine("Starting service...");
            ProcessStartInfo psiStart = new ProcessStartInfo("sc.exe", string.Format("start {0}", ServiceName))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using (Process pStart = Process.Start(psiStart))
            {
                pStart.WaitForExit();
                Console.WriteLine("Service start requested.");
            }

            Console.WriteLine("Installation complete. The MozaPowerService is now running in the background.");

            if (!string.Equals(Path.GetFullPath(originalExePath), Path.GetFullPath(exePath), StringComparison.OrdinalIgnoreCase))
            {
                if (ConsoleUtil.PromptYesNo("\nDelete the original executable at '" + originalExePath + "'? (Y/N): "))
                {
                    try
                    {
                        string batPath = Path.Combine(Path.GetTempPath(), "MozaDeleteOriginal.bat");
                        using (StreamWriter sw = new StreamWriter(batPath))
                        {
                            sw.WriteLine("@echo off");
                            sw.WriteLine("setlocal enabledelayedexpansion");
                            sw.WriteLine(string.Format("set \"target={0}\"", originalExePath));
                            sw.WriteLine("set tries=0");
                            sw.WriteLine(":retry");
                            sw.WriteLine("set /a tries+=1");
                            sw.WriteLine("del /F /Q \"%target%\" >nul 2>&1");
                            sw.WriteLine("if exist \"%target%\" (");
                            sw.WriteLine("    if !tries! GEQ 60 (");
                            sw.WriteLine("        goto end");
                            sw.WriteLine("    )");
                            sw.WriteLine("    timeout /t 1 >nul");
                            sw.WriteLine("    goto retry");
                            sw.WriteLine(")");
                            sw.WriteLine(":end");
                            sw.WriteLine("del \"%~f0\"");
                        }

                        ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", string.Format("/c \"\"{0}\"\"", batPath))
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false
                        };
                        Process.Start(psi);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Failed to schedule deletion of original executable: " + ex.Message);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error during installation: " + ex.Message);
        }
    }

    public static void Uninstall(bool deleteSelf)
    {
        try
        {
            if (!IsServiceInstalled())
            {
                Console.WriteLine("MozaPowerService is not currently installed.");
                return;
            }

            if (!ConsoleUtil.PromptYesNo("\nProceed with uninstalling the MozaPowerService Windows service? (Y/N): "))
            {
                Console.WriteLine("Uninstallation cancelled.");
                return;
            }

            Console.WriteLine("Stopping service: " + ServiceName);
            ProcessStartInfo psiStop = new ProcessStartInfo("sc.exe", string.Format("stop {0}", ServiceName))
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (Process pStop = Process.Start(psiStop)) 
            {
                pStop.WaitForExit();
            }

            System.Threading.Thread.Sleep(1500);

            Console.WriteLine("Deleting service: " + ServiceName);
            ProcessStartInfo psiDelete = new ProcessStartInfo("sc.exe", string.Format("delete {0}", ServiceName))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using (Process pDelete = Process.Start(psiDelete))
            {
                pDelete.WaitForExit();
                Console.WriteLine(pDelete.StandardOutput.ReadToEnd().Trim());
            }

            Console.WriteLine("Uninstallation complete.");

            if (deleteSelf)
            {
                DeleteSelf();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error during uninstallation: " + ex.Message);
        }
    }

    private static void DeleteSelf()
    {
        try
        {
            Console.WriteLine("Preparing to remove application files...");
            string exePath = Assembly.GetExecutingAssembly().Location;
            string dir = Path.GetDirectoryName(exePath);

            string batPath = Path.Combine(Path.GetTempPath(), "MozaCleanup.bat");
            
            using (StreamWriter sw = new StreamWriter(batPath))
            {
                sw.WriteLine("@echo off");
                sw.WriteLine("ping 127.0.0.1 -n 4 > nul");
                sw.WriteLine(string.Format("del /Q \"{0}\\*.*\"", dir));
                sw.WriteLine(string.Format("rmdir /Q \"{0}\"", dir));
                sw.WriteLine(string.Format("del \"%~f0\""));
            }

            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", string.Format("/c \"{0}\"", batPath))
            {
                CreateNoWindow = true,
                UseShellExecute = false
            };
            Process.Start(psi);
            
            Console.WriteLine("Cleanup initiated. The application will now exit and remove its folder.");
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to initiate self-deletion: " + ex.Message);
        }
    }
}

// =======================================================================================
// SECTION 7: Elevation, Entry Point & Execution Driver
// =======================================================================================

public static class ElevationUtil
{
    public static bool IsAdmin()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void RelaunchElevated(string[] args)
    {
        string exeName = Assembly.GetExecutingAssembly().Location;
        string argsString = string.Join(" ", args);

        ProcessStartInfo startInfo = new ProcessStartInfo(exeName, argsString)
        {
            UseShellExecute = true,
            Verb = "runas"
        };

        try
        {
            Process.Start(startInfo);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Console.WriteLine("Elevation was cancelled. This operation requires administrator privileges.");
        }
    }
}

public class Program
{
    public const string Version = "0.8.0";
    public static string InstalledSettingsArgument = "1111111";

    public static void Main(string[] args)
    {
        foreach (string argument in args)
        {
            if (ServiceSettings.IsValid(argument))
            {
                InstalledSettingsArgument = argument;
                break;
            }
        }

        if (!Environment.UserInteractive)
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new MozaPowerService()
            };
            ServiceBase.Run(ServicesToRun);
            return;
        }

        if (args.Length == 0)
        {
            bool serviceExists = ServiceInstallerUtil.IsServiceInstalled();

            if (serviceExists)
            {
                ShowHelp();
                return;
            }

            Console.Write("No service named 'MozaPowerService' is installed. Install now? (Y/N): ");
            string resp = Console.ReadLine();
            if (!string.IsNullOrEmpty(resp) && resp.Trim().StartsWith("y", StringComparison.OrdinalIgnoreCase))
            {
                if (!ElevationUtil.IsAdmin())
                {
                    Console.WriteLine("Elevating privileges...");
                    ElevationUtil.RelaunchElevated(new string[] { "install" });
                    return;
                }

                ServiceInstallerUtil.Install(null);
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            ShowHelp();
            return;
        }

        string command = args[0].ToLowerInvariant();

        if (command == "help" || command == "/?" || command == "-?" || command == "-h" || command == "--help" || command == "/help" || command == "?")
        {
            ShowHelp();
            return;
        }

        if (command == "install" || command == "uninstall" || command == "delete" || command == "testlog")
        {
            string installSettingsArgument = null;
            if (command == "install")
            {
                if (args.Length > 2)
                {
                    Console.WriteLine("Invalid install command. Use: MozaPowerService install [seven digits of 0 or 1].");
                    return;
                }

                if (args.Length == 2)
                {
                    installSettingsArgument = args[1];
                    if (!ServiceSettings.IsValid(installSettingsArgument))
                    {
                        Console.WriteLine("Invalid install settings. Expected exactly seven digits containing only 0 or 1.");
                        return;
                    }
                }
            }

            // Avoid unnecessary elevation and file changes when the requested service state already exists.
            if (command == "install" && ServiceInstallerUtil.IsServiceInstalled())
            {
                Console.WriteLine("MozaPowerService is already installed.");
                return;
            }

            if (command == "uninstall" || command == "delete")
            {
                if (!ServiceInstallerUtil.IsServiceInstalled())
                {
                    Console.WriteLine("MozaPowerService is not currently installed.");
                    return;
                }
            }

            if (!ElevationUtil.IsAdmin())
            {
                Console.WriteLine("Elevating privileges...");
                ElevationUtil.RelaunchElevated(args);
                return;
            }

            if (command == "install")
            {
                ServiceInstallerUtil.Install(installSettingsArgument);
            }
            else if (command == "uninstall")
            {
                ServiceInstallerUtil.Uninstall(false);
            }
            else if (command == "delete")
            {
                ServiceInstallerUtil.Uninstall(true);
            }
            else if (command == "testlog")
            {
                Console.WriteLine("Executing manual 'testlog' command...");
                bool result = MozaCommunicator.SendCommand(true, true, true);

                if (result)
                {
                    Console.WriteLine("Command completed successfully.");
                }
                else
                {
                    Console.WriteLine("Command failed. Ensure the wheelbase is connected and powered via the main switch.");
                }
            }

            if (command != "delete")
            {
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
            }
            return;
        }

        if (command == "on" || command == "off")
        {
            bool enable = (command == "on");

            Console.WriteLine(string.Format("Executing manual '{0}' command...", command.ToUpper()));
            bool result = MozaCommunicator.SendCommand(enable, true);

            if (result)
            {
                Console.WriteLine("Command completed successfully.");
            }
            else
            {
                Console.WriteLine("Command failed. Ensure the wheelbase is connected and powered via the main switch.");
            }
            return;
        }

        Console.WriteLine("Unknown command: " + command);
        ShowHelp();
    }

    private static void ShowHelp()
    {
        Console.WriteLine("=============================================================");
        Console.WriteLine(" MozaPowerService - Background Manager for Moza Wheelbases");
        Console.WriteLine("=============================================================");
        Console.WriteLine("Usage: MozaPowerService.exe [command]");
        Console.WriteLine("");
        Console.WriteLine("Service Management (Requires Administrator):");
        Console.WriteLine("  install       Installs and starts the background Windows Service.");
        Console.WriteLine("  install [set] Installs with the specified settings [set]. (See Below)");
        Console.WriteLine("  uninstall     Stops and removes the Windows Service.");
        Console.WriteLine("  delete        Uninstalls the service and self-deletes the application.");
        Console.WriteLine("");
        Console.WriteLine("Manual Operations:");
        Console.WriteLine("  on           Manually send the ON command to the wheelbase.");
        Console.WriteLine("  off          Manually send the OFF command to the wheelbase.");
        Console.WriteLine("");
        Console.WriteLine("  testlog      Generates a diagnostic log of connected Moza/USB devices.");
        Console.WriteLine("");
        Console.WriteLine("Settings Configuration:");
        Console.WriteLine("  Enter a seven-digit string of 0s and 1s to configure the service's behavior.");
        Console.WriteLine("  1111111");
        Console.WriteLine("  ││││││└ Enable Updates: Automatically download and install MozaPowerService updates when available.");
        Console.WriteLine("  │││││└ EnableOnStop: Send OFF when service stops. Safe fallback in case OnShutdown fails to get COM handle.");
        Console.WriteLine("  ││││└ EnableResumeAutomatic: Send ON when resuming automatically via non-user events (e.g., wake timers).");
        Console.WriteLine("  │││└ EnableResumeSuspend: Send ON when resuming from Sleep or Hibernation triggered by user input.");
        Console.WriteLine("  ││└ EnableSuspend: Send OFF when the system enters Sleep or Hibernation.");
        Console.WriteLine("  │└ EnableOnShutdown: Send OFF when the computer is fully shutting down.");
        Console.WriteLine("  └ EnableOnStart: Send ON when the computer boots from a full shutdown.");
    }
}

public static class ConsoleUtil
{
    public static bool PromptYesNo(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            string resp = Console.ReadLine();
            if (string.IsNullOrEmpty(resp)) continue;
            string t = resp.Trim().ToLowerInvariant();
            if (t == "y" || t == "yes") return true;
            if (t == "n" || t == "no") return false;
            Console.WriteLine("Please answer 'Y' or 'N'.");
        }
    }
}