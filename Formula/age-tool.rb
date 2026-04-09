# Homebrew formula for age-tool
#
# A full featured AGE encryption management tool. Installs the
# pre-compiled binary for the current macOS architecture (arm64 or x86_64).
#
# Usage:
#   brew tap anveitch/age-tool https://github.com/anveitch/age-tool
#   brew install age-tool

class AgeTool < Formula
  desc "A full featured AGE encryption management tool for encrypting, decrypting and managing AGE key pairs with audit logging"
  homepage "https://github.com/anveitch/age-tool"
  version "1.0.0"
  license "MIT"

  # Select the correct binary URL and checksum based on the current architecture
  on_macos do
    on_arm do
      url "https://github.com/anveitch/age-tool/releases/download/v1.0.0/age-tool-macos-arm64"
      sha256 "a1176ae0ea9aa9bcad3916fccf18b0a51e1bc68c1ad2dda7bb9d9f779343b655"
    end

    on_intel do
      url "https://github.com/anveitch/age-tool/releases/download/v1.0.0/age-tool-macos-intel"
      sha256 "cbdc5162b34a6a6c02d26a1769646946a0ef164c41b58451ff10ba55ba9d214c"
    end
  end

  def install
    # The downloaded file is a single pre-compiled binary.
    # Determine the downloaded filename based on architecture.
    binary_name = if Hardware::CPU.arm?
      "age-tool-macos-arm64"
    else
      "age-tool-macos-intel"
    end

    # Make the binary executable and install it to the Homebrew bin directory
    chmod 0755, binary_name
    bin.install binary_name => "age-tool"
  end

  test do
    # Verify the binary runs and prints the main menu header.
    # age-tool is an interactive TUI app with no --version flag,
    # so we pipe "q" to quit immediately and check for the banner.
    output = pipe_output("#{bin}/age-tool", "q\n", 0)
    assert_match "age-tool: file encryption/decryption", output
  end
end
