# Decrypt and decompress Home Assistant backups

## Why?

[Home Assistant](https://www.home-assistant.io) backups are are [tar](https://en.wikipedia.org/wiki/Tar_(computing)) archive files containing subarchives for various components and add-ons. Those subarchives are compressed and, since Home Assistant [2025.1](https://www.home-assistant.io/blog/2025/01/03/release-20251/), also forcefully encrypted.

While Home Assistant is a great home automation tool, the choice to use a custom archive format and custom encryption is just a horrible idea. You end up with [broken padding](https://github.com/pvizeli/securetar/issues/19) in your backups and users unable to [recover files](https://community.home-assistant.io/t/decryption-tool-for-backups-and-option-to-not-encrypt-backups/821719) from the backup using standard tools. Furthermore, [not giving users control](https://github.com/home-assistant/core/issues/134734) over compression or encryptions makes integration with real backup systems and implementing a sane [backup strategy](https://docs.borgbase.com/strategy) difficult.

Modern backup systems like [Borg Backup](https://borgbackup.org/) can deduplicate, compress and encrypt the data. Instead, the ad-hoc Home Assistant backup solution generates blobs that waste your throughput and storage. This makes an [offsite backup](https://www.borgbase.com) or frequent snapshotting with long history difficult. Also, when those backup archives cannot be opened and analyzed using standard tools, partial recovery, backup validation or manual recovery are impossible.

Let's fix it!

## How?

Download the tool, make it executable and run it. It was tested on Mac and Linux, but I see no reason why it wouldn't run on Windows.

```
./borgify-ha-backup.py automatic_backup_2025_1_4.tar decrypted_backup_2025_1_4.tar
```

The tool will ask you for your encryption key. You can also specify it via ```-p YOUR-ENCR-YPIO-NKEY-FROM-SETT-INGS```.

If it complains about missing crypto libraries, run

```
pip3 install pycryptodome
```

You can validate that the produced tar archive (and other archives embedded in it) open in standard tools.

If you're lucky, you might even be able to use the standard Home Assistant mechanism to recover from the resulting archive. That's one of the project goals, but as for anything here - no guarantees.

## Further reading

Run ```./borgify-ha-backup.py -h``` to see all available options.

Read the comments in the source code or the source code itself to learn more about Home Assistant backup format horrors ;-)

## Related projects

* https://github.com/sabeechen/decrypt-ha-backup - this tool did not work for me, but I learned a lot from it.
* https://github.com/cogneato/ha-decrypt-backup-tool - this worked for me, but I wanted something that just converts the archive.
