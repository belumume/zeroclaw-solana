# Capture rig — verified settings for the demo shoot

Every number here was produced by running the thing, not by reading documentation. Where a route
failed, the failure is recorded with its evidence, because the failures are the expensive part: two
of the three below exit 0 while producing nothing usable, so a shoot that trusts an exit code
discovers the problem in the edit.

Verified 2026-08-05 on this machine. Re-run the checks before rolling; a Windows update can change
which console host launches.

## The finding that matters most: the default console captures BLACK

`cmd.exe` on Windows 11 is hosted by Windows Terminal, which is GPU-composited. `ffmpeg -f gdigrab`
attaches to it, records for the full duration, writes a valid MP4 and exits 0. The file contains
nothing.

Measured, on a window whose text was plainly visible on screen at the time:

| route | bytes / 4s | frame mean | frame stddev | OCR |
|---|---|---|---|---|
| `cmd.exe` (Windows Terminal host) | 8,892 | **0** | **1** | nothing |
| `conhost.exe cmd.exe /k …` | 32,885 | 13 | 14 | full text recovered |

The mean of 0 is the whole story. 8,892 bytes for four seconds of 1482x762 is a static black frame
compressing to almost nothing, and no error is raised anywhere in the chain.

**So: always launch the on-camera terminal through `conhost.exe` explicitly.**

    Start-Process -FilePath "$env:SystemRoot\System32\conhost.exe" `
      -ArgumentList "cmd.exe /k <your command>" -WindowStyle Normal

## Two smaller traps that each cost a take

**The window title must match byte for byte, and `title X && …` adds a trailing space.** cmd's
`title` builtin swallows everything up to the `&&`, including the space before it, so the window is
named `ZCXCAP ` and `-i "title=ZCXCAP"` reports `Can't find window` while PowerShell finds it fine.
Write `title ZCXCAP&& …` with no space. Confirm before rolling:

    Get-Process | ? { $_.MainWindowTitle -like "ZCX*" } | % { "[" + $_.MainWindowTitle + "]" }

The brackets are the point. They make a trailing space visible.

**Console windows have odd pixel dimensions and yuv420p requires even.** The test window was
1481x761 and libx264 died with `Invalid argument (-22)` and `Nothing was written into output file`.
Pad rather than resize, so no text is resampled:

    -vf "pad=ceil(iw/2)*2:ceil(ih/2)*2"

## The verified capture command

    ffmpeg -y -f gdigrab -framerate 30 -i "title=ZCXCAP" \
      -vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" \
      -c:v libx264 -crf 18 -pix_fmt yuv420p out.mp4

## The check that must run after every take, before the window is closed

A take is not verified by its duration or its exit code. Both were green on the black capture.

    ffmpeg -y -i out.mp4 -vf "select=eq(n\,20)" -fps_mode passthrough probe.png
    magick probe.png -colorspace Gray -format "mean=%[fx:int(mean*255)] sd=%[fx:int(standard_deviation*255)]\n" info:
    "C:/Program Files/Tesseract-OCR/tesseract.exe" probe.png stdout --psm 11

`mean=0` means black, reshoot. A luminance reading alone is not sufficient either: it proves light,
not legibility. The OCR is the positive control, and it must return the words that were on screen.
`--psm 11` is load-bearing for terminal and UI layouts; the default page-segmentation mode assumes a
uniform text block and silently returns a fraction of what is there.

Tesseract is installed but **not on PATH**: `C:/Program Files/Tesseract-OCR/tesseract.exe`.

## Resolution

The previously shipped cut is **1280x720** (`ffprobe` on `.demo-assets/cut/zeroclaw-solana-demo.mp4`:
1280x720, 159.518s, 4,963,860 bytes). A judge watching full-screen on a 1080p or better display sees
soft terminal text, and terminal text is most of this video. Capture at 1080p minimum. Prefer
capturing larger and downscaling with `-vf scale=1920:-2:flags=lanczos`, which is sharper than
capturing at target size.

## Toolchain, as measured rather than assumed

| tool | state |
|---|---|
| ffmpeg / ffprobe | 8.0-full, on PATH |
| ImageMagick | 7.1.1 Q16-HDRI, `magick` on PATH |
| OBS Studio | installed, `C:\Program Files\obs-studio\bin\64bit\obs64.exe`, not on PATH |
| ShareX | installed, `C:\Program Files\ShareX\ShareX.exe` |
| DaVinci Resolve | installed, `C:\Program Files\Blackmagic Design\DaVinci Resolve\Resolve.exe` |
| Tesseract | installed, not on PATH, path above |
| scrcpy / adb | being installed; see below |

**Phone is Android.** Determined from the device list rather than asked: Windows reports a
`SAMSUNGDEVICE` PnP entry, and `%USERPROFILE%\.android` does not exist, so adb has never run here.
That settles the mirroring route — scrcpy, not Phone Link, not filming the handset.

**scrcpy install trap, recorded because it exits 0 while doing nothing.** `winget install --id
Genymobile.scrcpy` without a source returns exit code 0 and installs nothing, printing only
"Please specify one of them using the --source option". Pin the source:

    winget install --id Genymobile.scrcpy --source winget --accept-package-agreements --accept-source-agreements

Verify by locating the binary, not by the exit code.

## Why scrcpy rather than filming the handset

The listing says "terminal + phone is perfect", and a physically-held phone carries warmth a
mirrored window does not. But a filmed screen brings moiré, glare, autofocus hunting and handheld
wobble, and it caps legibility exactly where the judge most needs to read a chat message.

scrcpy mirrors the device losslessly at native resolution over USB and appears as an ordinary window
that OBS captures cleanly. The resolution: **mirror the screen for anything the judge must READ, and
film the physical handset only for a beat whose job is to prove a real human is holding a real
phone.** They are different shots with different purposes and the demo can afford both.
