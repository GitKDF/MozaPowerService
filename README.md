# MozaPowerService

Windows service that toggles work mode on and off for supported Moza wheelbases in response to PC power events.  If you leave your wheelbase on all of the time (since the tiny power button that you have to push and hold is annoyingly on the back!), this will cycle work mode to put the wheelbase to "sleep" when not in use.  I know some people leave it on all of the time, but this bothered me with the waste of power and some level of wear and tear on the wheelbase itself.

## Features

- Sends the ON command when the service starts.
- Sends the OFF command during shutdown, sleep, or service stop, according to configuration.
- Works whether MOZA Pit House is running or not.
- Checks GitHub for a newer release at service startup and daily thereafter.
- Will not cycle work mode when updating--no surprise loss of wheel power mid race due to an update.

## Requirements

- Windows 10/11 (with the .NET 4.x runtimes, which are installed by default) .
- Administrator privileges for installation, service management, and self-updates.
- A supported Moza wheelbase.

The following devices are currently supported:

| Model            | Vendor ID | Product ID | Tested |
|------------------|-----------|------------|--------|
| R16, R21         | VID_346E  | PID_0000   |        |
| R9, R9v2, R9v3   | VID_346E  | PID_0002   | X (v2) |
| R5               | VID_346E  | PID_0004   |        |
| R3               | VID_346E  | PID_0005   |        |
| R12, R12v2       | VID_346E  | PID_0006   |        |

## Thanks to:
The Boxflat project, an open source linux alternative to MOZA Pit House.  They reverse engineered the serial protocol used to send the wheelbase work mode commands.
https://github.com/Lawstorant/boxflat

List of VID/PIDs obtained from:
https://forum.kw-studios.com/index.php?threads/all-moza-deviceids-bases-and-pedals.19303/

## Installation

Download and run `MozaPowerService.exe` to install with the default settings.

To install with custom settings values (see below):

```text
MozaPowerService.exe install 1111111
```

The executable will be copied to: %ProgramFiles%\MozaPowerService\MozaPowerService.exe

It then creates and starts the `MozaPowerService` Windows service.

## Settings

The settings value contains exactly seven characters. Each character is either `1` to enable a behavior or `0` to disable it.

The order is:

```text
1111111
│││││││
││││││└ Enable automatic updates
│││││└─ Enable OFF command when the service stops
││││└── Enable ON command after automatic resume (when windows wakes itself)
│││└─── Enable ON command after user-initiated resume
││└──── Enable OFF command before sleep or hibernation
│└───── Enable OFF command during system shutdown
└────── Enable ON command when the service starts
```

Examples:

- `1111111`: enable every behavior.
- `1111110`: enable power-event behavior but disable automatic updates.
- `1100000`: enable only startup and shutdown events, no automatic updates.

## Commands
```text
MozaPowerService.exe help
   or: /? -? ? -h --help /help
MozaPowerService.exe install [seven-digit-settings]
MozaPowerService.exe uninstall
MozaPowerService.exe delete
MozaPowerService.exe on
MozaPowerService.exe off
MozaPowerService.exe testlog
```

`on` and `off` send a command immediately, useful for creating shortcuts to control the wheelbase manually.

`testlog` generates diagnostic information and saves it to the installation folder.  Please run this if your wheelbase is not detected/working and include this info in an issue report.

## Communication behavior

When MOZA Pit House is running, the service first attempts to duplicate and use Pit House's existing COM handle. The write is considered successful only when the native write completes successfully and the exact packet length is reported as written.

If Pit House is not running, or handle duplication/write verification fails, the service waits briefly when necessary and then attempts an exclusive raw COM-port write. Hardware and port-lock errors are caught so they do not terminate the service.

## Automatic updates

Automatic updates are enabled by the seventh settings digit. The service checks:

```text
https://github.com/GitKDF/MozaPowerService/releases/latest
```

when the service starts and then once every 24 hours while the service is running. A new version wil be downloaded and installed automatically if the update setting is enabled.  It will NOT cycle your wheelbase during an update, so no surprise loss of wheel functionality mid-race due to an update!

## Building locally

This project intentionally compiles directly with the .NET Framework C# compiler rather than using a project file or SDK-style build.

From an elevated PowerShell window in the same directory as the source file:

```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /out:MozaPowerService.exe MozaPowerService.cs
```

The executable version is defined near the top of `MozaPowerService.cs` in `BuildInfo.Version`. The update routine uses that value to check for updates.  If you are building locally, either install with updates disabled, or change that to a very high version number.

## Send me a tip
CashApp (preferred)
https://cash.app/$KristopherFarrin

Paypal (they take $.49, that's a lot when I expect a few people may send a dollar or two!)
https://paypal.me/GitKDF
