# BITSServer

BITSServer is a basic Python3 server for using the Windows Binary Intelligent Transfer Service protocol (BITS), supporting file upload and download from Windows clients using the built-in `bitsadmin.exe` command-line tool, `BitsTransfer` PowerShell module, or COM interface.

**WARNING: BITSServer is uses Python's built-in http.server library and is NOT recommended for production.**

## Installation

```
git clone <url> && cd bitsserver/
pip3 install .
```


## Server Operation

BITSServer supports uploading/downloading any files from the working directory.
The server logs will write to `bitsserver.log`

You can run the server from the command line:

```
python3 -m bitsserver 80
```

Alternatively, build and run the docker container:

```
docker build --tag bitsserver .
docker run bitsserver -d -p 80:80 -v /tmp/bits:/app
```
In this example, we are mapping the local `/tmp/bits` directory to the container's working directory (`/app`), acting as our download/upload directory, and log destination.


## Client Operation

On the client-side, create a transfer job using the BITS client of your choice. For instance, uploading a file to the server using `bitsadmin.exe`:

```
bitsadmin /transfer <name> /upload http://<server>/<filename> <filepath>
```

Using PowerShell's `BitsTransfer` module is another option

```
Import-Module BitsTransfer
Start-BitsTransfer -TransferType Upload -Source <filepath> -Destination http://<server>/<filename> -DisplayName <name>
```

These are simple examples. For custom client development, BITS jobs can be created and managed locally with the [COM interface](https://docs.microsoft.com/en-us/windows/win32/bits/common-classes), or [remotely with WinRM](https://docs.microsoft.com/en-us/windows/win32/bits/using-winrm-windows-powershell-cmdlets-to-manage-bits-transfer-jobs). 
