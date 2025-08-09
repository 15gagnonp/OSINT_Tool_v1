# VirusTotal Lookup Script

## Usage

1. Copy `.env.example` to `.env` and add your VirusTotal API key.
2. Edit `config.json` to set your desired rate limit (default: 4 requests/minute).
3. Prepare a text file with one IP address or domain per line.
4. Run the script:

   ```
   python main.py --input input.txt --type [ip|domain]
   ```

## Security

- **Never share your API key.**
- `.env` and `config.json` should be added to `.gitignore`.
- API keys are loaded from environment variables, not hardcoded.

## Limitations

- Only supports one type of input per run (all IPs or all domains).
- Results are printed to the terminal.
- Handles basic input validation and API errors.

## API Key Setup

- Store your API key in a `.env` file as `VT_API_KEY`.

## Example Input

```
8.8.8.8
1.1.1.1
```
or
```
example.com
google.com
```