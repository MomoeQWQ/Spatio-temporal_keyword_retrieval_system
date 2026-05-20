# CLI ? CSP ??

?????

```bash
python run_owner_setup.py
python run_all.py "ORLANDO"
python run_csp.py --port 8001 --aui apps/cli/aui.pkl --user-db apps/cli/users_db.json
python run_cli.py --query "ORLANDO" --expansion-mode fallback --retrieval-mode legacy
python run_cli.py --query "ORLANDO" --expansion-mode none --retrieval-mode rapq_plus
```

`client.py` ?? `none`?`fallback`?`gemini` ????????? `legacy`?`rapq`?`rapq_plus` ???????
