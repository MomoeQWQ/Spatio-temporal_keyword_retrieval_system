# GUI Demo

## Files
- `client_gui.py`: GUI client with auth login, expansion mode (`none/fallback/gemini`), and weighted ranked results.
- `server_gui.py`: GUI controller that starts/stops multiple auth-enabled `csp_server` nodes and initializes `users_db.json`.

## Workflow
1) Generate index
```
python online_demo/owner_setup.py
```
2) Start CSP GUI
```
python gui_demo/server_gui.py
```
Choose `aui.pkl`, set `users_db.json` path and ports (default 8001/8002/8003), click **Start Servers**.

3) Start client GUI
```
python gui_demo/client_gui.py
```
Pick `aui.pkl`, `K.pkl`, `conFig.ini`, dataset CSV.
Enter endpoints + user credentials (default `alice/alice123`), choose expansion mode, then click **Run Query**.

## Tips
- Multi-keyword AND: separate keywords by spaces, e.g. `ORLANDO ENGINEERING UNIVERSITY`.
- Spatial range: append `; R: lat_min,lon_min,lat_max,lon_max`.
- Ranked output now includes score and hit source (`base`, `base+Nexp`, `Nexp`).
- Result table supports click-to-sort on each column (ascending/descending toggle).
- If `gemini` mode is unavailable, expansion automatically falls back to local synonyms.
