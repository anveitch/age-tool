# age-tool user guide

age-tool keeps your files private. It turns a file into a locked copy that only the right person can open, even if someone else gets hold of it. This guide covers the desktop app on Linux. You don't need to use a terminal.

## Words you'll see

| Word | What it means |
|---|---|
| **Encrypt** | Make a locked copy of a file. The copy has `.age` added to its name, e.g. `Tax return.pdf.age`. Your original is not changed. |
| **Decrypt** | Unlock a `.age` file to get the original back. |
| **Key** | What you need to lock and unlock files. Each key has two halves: |
| **Public key** | The half you **give out**. Anyone who has it can lock files for you. It's a single line starting with `age1`. It is safe to email or message. |
| **Private key** | The half you **keep**. It's the only thing that can unlock files locked for you. It stays on your computer, protected by your passphrase. Never send it to anyone. |
| **Passphrase** | The password that protects your private key. You type it each time you decrypt. |
| **Contact** | Someone else's public key, saved so you can lock files for them. |

> **Important:** if you forget your passphrase, or lose your private key, files locked for that key **can't be recovered** by anyone, including the author of age-tool. See [Keep your key safe](#keep-your-key-safe).

## 1. Install age-tool

1. Go to the [age-tool releases page](https://github.com/anveitch/age-tool/releases/latest) and download:
   - **`age-tool-linux-x64.AppImage`** for almost all PCs and laptops
   - **`age-tool-linux-arm64.AppImage`** only for ARM computers (for example a Raspberry Pi)
2. Move the file somewhere it can stay, such as a folder called `Applications` in your home folder. (If you move it later, see [Troubleshooting](#troubleshooting).)
3. Allow it to run: in Files, right-click it, choose **Properties**, and turn on **Executable as Program** (on some versions: the **Permissions** tab, tick **Allow executing file as program**).
4. Double-click it to open age-tool.

The first time it opens, age-tool asks whether to add itself to your desktop. Choose **Add to desktop**. This puts age-tool in your app menu, lets you double-click `.age` files to decrypt them, and adds **Encrypt** and **Decrypt** to the right-click menu of your files.

<img src="images/add-to-desktop.png" alt="Add age-tool to your desktop? With Not now and Add to desktop buttons" width="620">

After that, open age-tool from your app menu like any other app (search for "age-tool" or "encrypt").

age-tool works on Ubuntu 22.04 or newer, and other Linux systems of a similar age (Linux Mint 21, Debian 12, Fedora 36 and later).

## 2. The home screen

<img src="images/home.png" alt="The age-tool home screen with Encrypt a file, Decrypt a file and My keys buttons" width="620">

- **Encrypt a file**: lock a file.
- **Decrypt a file**: unlock a `.age` file.
- **My keys**: your keys and contacts.
- **View activity**: what you've done with age-tool.
- **Desktop integration**: add age-tool to (or remove it from) your app and right-click menus.

You can also drag files onto the window.

## 3. Create your key

You need your own key before anyone (including you) can lock files for you. You only do this once.

1. Choose **My keys**, then **Create a key**.
2. Give it a **name**, like `laptop`. A **nickname** such as "My laptop key" is optional, and is what age-tool shows in lists.
3. Choose a **passphrase** of at least 12 characters, and type it again to confirm. A few unrelated words work well, for example `orange kettle march piano`. age-tool shows how strong it is as you type.
4. Choose **Create**.

<img src="images/create-key.png" alt="The Create a key form with name, nickname, passphrase and confirmation" width="620">

Your new key appears under **My keys** with a house icon. Contacts you add later have a person icon.

<img src="images/keys.png" alt="My keys showing a contact and your own key" width="620">

## 4. Encrypt a file

1. Choose **Encrypt a file** (or right-click a file in Files and choose **Encrypt with age-tool**).
2. **Choose a file...** if one isn't already chosen.
3. Under **Who is it for?**, choose who should be able to open it:
   - **your own key**, marked "(you)", to keep a file private for yourself
   - **a contact**, to send it to them
4. Choose **Encrypt**.

<img src="images/encrypt.png" alt="The Encrypt a file screen with the file chosen and a list of people to encrypt for" width="620">

The locked copy is saved next to the original, ending in `.age`. Your original isn't changed, so delete it yourself if you no longer want an unlocked copy.

**Note:** once a file is encrypted for a contact, only they can open it. Not even you can open it with your own key. To keep a copy you can open too, encrypt it a second time for yourself.

## 5. Decrypt a file

1. **Double-click** the `.age` file, or right-click it and choose **Decrypt with age-tool**, or choose **Decrypt a file** in age-tool.
2. If you have more than one key, choose which one under **Which of your keys?**.
3. Choose **Decrypt**, then type your passphrase.

<img src="images/decrypt.png" alt="The Decrypt a file screen with the encrypted file and your key chosen" width="620">

The unlocked file is saved next to the `.age` file, without the `.age` ending.

You have **3 tries** at the passphrase. After a wrong one, age-tool tells you how many are left. After three, start again.

<img src="images/passphrase.png" alt="The passphrase box, saying the passphrase is incorrect with 2 attempts left" width="620">

If a file with the same name is already there, age-tool asks first. **Replace** overwrites it with the unlocked copy. **Skip** leaves it alone and saves nothing.

<img src="images/replace.png" alt="Replace existing file? With Skip and Replace buttons" width="620">

If age-tool says the file wasn't encrypted for any of your keys, it was locked for someone else's key. Ask the sender to encrypt it again using your public key.

## 6. Share your public key

For someone to send you private files, they need your **public** key.

1. Choose **My keys**, select your key, then **Share public key**.
2. Choose **Copy** and paste it into an email or message, or **Save a copy...** to save it as a file you can attach.

<img src="images/share.png" alt="The Share public key box showing a key starting age1, with Copy and Save a copy buttons" width="620">

Your public key is safe to share with anyone. **Never** send your passphrase or private key. age-tool never shows or shares the private key.

## 7. Add a contact

To lock files for someone else, you need their public key.

1. Ask them for it. It's one line starting with `age1`, or a file ending in `.pub`.
2. Choose **My keys**, then **Add a contact**.
3. Give them a name and, if you like, a nickname such as their full name.
4. Paste their key, or choose **Load from a .pub file...**.
5. Choose **Add**.

<img src="images/add-contact.png" alt="The Add a contact form with name, nickname and public key" width="620">

They now appear under **Who is it for?** when you encrypt.

If you paste a **private** key by mistake (it starts with `AGE-SECRET-KEY`), age-tool refuses it. Ask the person to delete that message, because a private key should never be sent.

## 8. Other things you can do with keys

Select a key under **My keys**, then:

- **Rename**: change the nickname shown in lists.
- **Protect**: add a passphrase to a private key that doesn't have one (for example, one made with other tools). age-tool won't use a private key until it's protected.
- **Delete**: remove a key or contact. Deleting **your own** key means files locked for it can never be opened again, so age-tool asks you to confirm.

## 9. Activity

**View activity** on the home screen lists what you've encrypted, decrypted and created, newest first. It records file names and dates, never passphrases or keys.

<img src="images/activity.png" alt="The activity list showing recent encrypt, decrypt and key creation entries" width="620">

## Keep your key safe

Your keys are kept in a hidden folder in your home folder:

```
~/.local/share/age-tool/keys
```

**Back it up.** If your computer breaks, files locked for your key can only be opened with a copy of this folder **and** your passphrase. To back it up:

1. In Files, open your home folder and press **Ctrl+H** to show hidden folders.
2. Open `.local`, then `share`, and copy the `age-tool` folder to a USB stick or another safe place.

The private key in the backup is still protected by your passphrase, but keep the backup somewhere private anyway.

To restore it on a new computer, copy the `age-tool` folder back to the same place before opening age-tool.

## Troubleshooting

**age-tool doesn't open when I double-click it.**
Check step 3 of [Install](#1-install-age-tool). If it still doesn't open, your system may be missing FUSE, which AppImages use. Open a terminal in the folder and run `./age-tool-linux-x64.AppImage --appimage-extract-and-run`, or install FUSE (`sudo apt install fuse3` on Ubuntu and Mint).

**The right-click entries don't appear.**
Close every Files window and open it again. In Files (GNOME), they're under **Scripts** in the right-click menu. On KDE, log out and back in if they still don't show.

**I moved or updated the age-tool file, and the menus stopped working.**
Open the new copy. age-tool asks whether to update its menus; choose **Update**. (Or use **Desktop integration** on the home screen.)

**It says my key isn't protected.**
Select it under **My keys** and choose **Protect** to give it a passphrase.

**I forgot my passphrase.**
There's no way to recover it, and files locked for that key can't be opened. Create a new key, share the new public key, and ask people to send files again.

## Removing age-tool

1. Open age-tool, choose **Desktop integration**, then **Remove**. This removes the menu entries and right-click entries.
2. Delete the AppImage file.

Your keys stay in `~/.local/share/age-tool`, so keep that folder if you might want them again.

## Using the command line

age-tool also has a command-line version for technical users, sharing the same keys. See the [README](../README.md#command-line-guide).
