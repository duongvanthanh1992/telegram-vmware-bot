import os
import subprocess
from dotenv import load_dotenv
from bot.command_parser import telegram_bot


def decrypt_env():
    passphrase = os.getenv("GPG_PASSPHRASE")
    if passphrase:
        subprocess.run(
            [
                "gpg",
                "--quiet",
                "--batch",
                "--yes",
                "--decrypt",
                "--pinentry-mode",
                "loopback",
                f"--passphrase={passphrase}",
                "--output",
                ".env",
                ".env.gpg",
            ],
            check=True,
        )
    else:
        subprocess.run(
            [
                "gpg",
                "--quiet",
                "--batch",
                "--yes",
                "--decrypt",
                "--output",
                ".env",
                ".env.gpg",
            ],
            check=True,
        )


def cleanup_env():
    if os.path.exists(".env"):
        os.remove(".env")


def clear_gpg_agent_cache():
    subprocess.run(["gpg-connect-agent", "reloadagent", "/bye"], check=True)


def main():
    """Main entry point for the Telegram Bot"""
    decrypt_env()
    load_dotenv(".env")
    cleanup_env()
    clear_gpg_agent_cache()
    print("Starting Telegram Bot...")
    telegram_bot()


if __name__ == "__main__":
    main()
