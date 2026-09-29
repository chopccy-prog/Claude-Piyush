# Running the bridge on the MassLynx PC (Windows)

The MassLynx acquisition PC is almost always Windows. Here is how to run the
bridge there unattended.

## 1. Install Python

Install Python 3.9+ from python.org. During install, tick **"Add Python to
PATH"**. Verify in a Command Prompt:

```
python --version
```

## 2. Get the code onto the PC

Copy the `masslynx_bridge` folder to, for example, `C:\masslynx_bridge`.

## 3. Install dependencies

```
cd C:\masslynx_bridge
python -m pip install -r requirements.txt
```

If you will use the SQL database sink, also:

```
python -m pip install SQLAlchemy psycopg[binary]   # or PyMySQL for MySQL
```

## 4. Configure

```
copy config.example.yaml config.yaml
notepad config.yaml
```

Set:
- `instrument_id` - a unique name for this PC.
- `collectors[].watch_dir` - the real folders LogLynx / OpenLynx export into.
- `sink.url` - your ERP ingest endpoint.

Put the API token in an environment variable, not the file:

```
setx MASSLYNX_BRIDGE_SINK_TOKEN "your-secret-token"
```

(Use `setx` so it persists; reopen the Command Prompt afterwards.)

## 5. Test before running unattended

```
:: validate config only
python -m masslynx_bridge --config config.yaml --check

:: single pass, prints what would be sent if you set sink.type: stdout
python -m masslynx_bridge --config config.yaml --once
```

## 6. Run it as a background service

### Option A - Task Scheduler (no extra software)

1. Open **Task Scheduler** > **Create Task**.
2. General tab: name it "MassLynx Bridge"; select **Run whether user is logged
   on or not**; tick **Run with highest privileges**.
3. Triggers: **At startup**.
4. Actions: **Start a program**
   - Program: `C:\Path\To\python.exe`
   - Arguments: `-m masslynx_bridge --config C:\masslynx_bridge\config.yaml`
   - Start in: `C:\masslynx_bridge`
5. Settings: tick **If the task fails, restart every 1 minute**, up to 3 times;
   and **If the running task does not end when requested, force it to stop**.

The bridge runs its own poll loop, so one long-running task is all you need.

### Option B - NSSM (runs as a true Windows Service)

[NSSM](https://nssm.cc/) wraps any program as a Windows service with automatic
restart and logging.

```
nssm install MassLynxBridge "C:\Path\To\python.exe" ^
  "-m" "masslynx_bridge" "--config" "C:\masslynx_bridge\config.yaml"
nssm set MassLynxBridge AppDirectory C:\masslynx_bridge
nssm set MassLynxBridge AppStdout C:\masslynx_bridge\logs\out.log
nssm set MassLynxBridge AppStderr C:\masslynx_bridge\logs\err.log
nssm set MassLynxBridge AppEnvironmentExtra MASSLYNX_BRIDGE_SINK_TOKEN=your-secret-token
nssm start MassLynxBridge
```

## 7. Confirm it is working

- Watch the log output (console, or the NSSM log files).
- On the ERP side, confirm records are arriving with the right `instrument_id`.
- `state\bridge_state.json` will appear and track each file's byte offset.

## Notes for the MassLynx PC

- Point `watch_dir` at a **dedicated export folder**, not MassLynx's internal
  data directories. Have LogLynx/OpenLynx export there on a schedule.
- If exports land on a **network share**, the polling loop (not inotify) is
  deliberately used so it stays reliable across share hiccups.
- The bridge only ever **reads** the export files. It never writes to or alters
  MassLynx data, so it cannot affect acquisitions or the validated system.
