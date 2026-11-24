# Telegram alerts

`loghunt watch` can send every alert to a Telegram chat through a bot. It is one more channel next to the console, the JSON lines file and the desktop popups, and it uses only the standard library (`urllib`).

## Set it up

1. In Telegram open [@BotFather](https://t.me/BotFather), send `/newbot`, pick a name and a username that ends in `bot`. BotFather answers with the **bot token**, something like `123456789:AAH...`.
2. Open your new bot, press **Start** and send it any message. A bot cannot write to you first, and the next step finds nothing until you have written to it.
3. Find your chat id. The token is a password, so read it without leaving it in the shell history:

   ```bash
   read -rs TOKEN
   curl -s "https://api.telegram.org/bot$TOKEN/getUpdates" | python3 -m json.tool | grep -A2 '"chat"'
   ```

   The number after `"id":` is the chat id. For a group it is negative. A public channel can be given as `@channelname`.
4. Put both into `~/.config/loghunt/loghunt.ini` (`loghunt init-config` creates it with mode 600):

   ```ini
   [telegram]
   bot_token = 123456789:AAH...
   chat_id = 123456789
   min_severity = high
   ```

   Or keep the token out of the file and use the environment instead. The variables win over the file:

   ```bash
   export LOGHUNT_TELEGRAM_TOKEN=123456789:AAH...
   export LOGHUNT_TELEGRAM_CHAT_ID=123456789
   ```

   The systemd service does not see your shell variables, so for the background service use the config file.
5. Test it:

   ```bash
   loghunt watch --test-notify
   ```

   The output must list `telegram` under `channels:` and the test message arrives in the chat.

## Which alerts are sent

Only findings at `min_severity` or above (default `high`), because a phone that buzzes for every scanner stops being read. The console and the file still get everything from `medium`. The test alert and the "N more findings" summary are always sent. Like the desktop popups, Telegram gets at most five alerts per batch of log lines, then one summary. `--no-telegram` turns the channel off for one run.

A message looks like this:

```
CRITICAL  ssh-login-after-bruteforce
address: 192.0.2.99
successful login as 'deploy' right after a brute force, the account may be compromised
T1078 Valid Accounts
2026-11-24 14:59:40
```

## If it does not work

The error is printed to stderr and never contains the token.

| Message | Usual reason |
|---|---|
| `telegram disabled, the bot token does not look right` | typo or a cut token, it must look like `123456789:AAH...` |
| `TelegramError (HTTP 401 Unauthorized)` | wrong or revoked token |
| `TelegramError (HTTP 400 Bad Request: chat not found)` | wrong chat id, or you never pressed Start in the bot chat |
| `TelegramError (HTTP 403 ...)` | you blocked the bot, or it was removed from the group |
| `URLError` | no network or DNS, the other channels keep working |

## Security notes

- The bot token lets anyone send messages as your bot. Do not commit it. If it leaks, send `/revoke` to BotFather. The config file is created with mode 600, and the token is only ever put in the request URL, never in logs or error text.
- Log lines are written by the attacker, so a username or a URL can contain anything. Messages are sent as plain text, without `parse_mode`, so nothing from a log line becomes formatting or a clickable preview. Control characters are replaced and the text is cut at 1000 characters.
- Alerts go to Telegram's servers over HTTPS. Bot messages are not end-to-end encrypted. They contain attacker addresses, tried usernames and request paths. Do not enable the channel if that must not leave the machine.
- The request has a 5 second timeout and there are no retries. If Telegram is unreachable the alert is still in the console, the file and the desktop popup, but it is not queued for later.
