**Install:** download `RockSign-….dmg`, open it and drag **RockSign** to **Applications**.

The first time you open it, macOS says it can't check the app for malware, because the app isn't
signed with a paid Apple developer certificate. Click **Done**, then go to **System Settings →
Privacy & Security**, scroll down and click **Open Anyway** next to RockSign. You only do this once
per version. Details and a Terminal alternative are in the [README](https://github.com/OWNER/REPO#install).

**Check the download (optional):** `gh attestation verify RockSign-*.dmg --repo OWNER/REPO`
confirms this file was built by GitHub Actions from this repository's source.
