// The same lists as crates/derm-core/src/destructive.rs's tests (E1-1), so the
// TypeScript reader and the Rust one are held to one set of answers beyond
// the shared fixture.
import { describe, expect, it } from "vitest";
import { destructive } from "./destructive.ts";

const asks: Array<[string, string]> = [
  ["rm -rf /", "command changes the filesystem root: `rm`"],
  ["sudo rm -rf /", "command changes the filesystem root: `rm`"],
  ["rm -rf --no-preserve-root /", "command changes the filesystem root: `rm`"],
  ["chmod -r 777 /", "command changes the filesystem root: `chmod`"],
  ["truncate -s 0 /etc/passwd", "command changes a system folder: `truncate`"],
  ["dd if=/dev/zero of=/dev/sda bs=1m", "command changes a disk device: `dd`"],
  ["mkfs.ext4 /dev/sda1", "command changes a disk device: `mkfs.ext4`"],
  ["wipefs -a /dev/nvme0n1", "command changes a disk device: `wipefs`"],
  ["kill -9 -1", "command signals every process: `kill`"],
  ["rm -rf /home/opone", "command changes a home folder: `rm`"],
  ["rm -rf ..", "command changes a parent folder: `rm`"],
  ["echo x > /etc/passwd", "command changes a system folder: `>`"],
];
const some = [
  "rm -rf //", "rm -rf /./", "rm -rf /tmp/..", "rm -rf /tmp/../etc/x", "rm -rf '/'", 'rm -rf "/etc"/x', "rm -rf -- /",
  "rm -rf /private/etc/hosts", "rm -rf ../..", "rm -rf ./../",
  "sudo -u root rm -rf /usr", "env x=1 nice chmod -r 777 /etc", "sh -c 'rm -rf /'", 'bash -lc "chown -r u /usr/lib"',
  "true && rm -rf /var/lib/x; echo done", "eval rm -rf /boot", "sudo sh -c 'echo x > /etc/hosts'", "sudo tee /etc/sudoers.d/x",
  "echo x | sudo tee -a /etc/hosts", "/bin/rm -rf /",
  "cp x /etc/cron.d/x", "cp -t /usr/bin x", "cp --target-directory=/etc x", "ln -sf /tmp/x /etc/ld.so.preload",
  "install -m 4755 x /usr/bin/x", "mv /etc/hosts .", "mv x /usr/bin/", "mv -t /tmp /home/u",
  "kill -s kill -1", "kill -- -1", "kill -1 -1", "sudo kill -kill -1", "tee /dev/sdcard",
  ...["sda", "sdb1", "nvme0n1p2", "mmcblk0", "disk2", "rdisk2", "mapper/root", "dm-0", "md0", "loop3", "mem"].map((d) => `shred /dev/${d}`),
];
const none = [
  "rm -rf build", "rm -rf ./node_modules", "rm -rf /tmp/build", "rm -rf /var/tmp/x /var/folders/ab/cd", "rm -rf ../sibling",
  "rm -rf /home/u/proj/target", "rm -rf /workspace/proj/dist", "chmod +x scripts/run.sh", "chmod -r 755 .", "chown u:g file",
  "cp /etc/hosts ./hosts.copy", "cp -r src /tmp", "cp tool /usr/local/bin/tool", "install -m 755 tool /opt/tool/bin/tool",
  "ln -s /usr/lib/x.so ./x.so", "mv build /tmp", "mv a b", "tee out.log", "echo x > out.txt", "echo x > /dev/null 2>&1",
  "cmd 2>/dev/null >&2", "echo x >> /tmp/log", "dd if=/dev/sda of=disk.img", "dd if=/dev/zero of=/dev/null", "mkfs.ext4 disk.img",
  "truncate -s 0 out.log", "kill -9 1234", "kill -1 1234", "kill -hup 77", "git commit -m 'rm -rf / is bad'", "echo 'x > /etc/passwd'",
  "grep -r 'chmod 777 /' docs", "cat /etc/hosts", "ls /", "# rm -rf /", "echo a # > /etc/x", "cp x /", "cp x /home/u",
  "mv -t /tmp build", "kill -1", "kill -1 55",
  ...["null", "zero", "stdout", "stderr", "tty", "shm/x", "fd/3", "urandom"].map((d) => `tee /dev/${d}`),
];

describe("step 7e: destructive commands (E1-1)", () => {
  it("names the class and the program", () => {
    for (const [text, want] of asks) expect([text, destructive(text)]).toEqual([text, want]);
  });
  it("asks for each of these", () => {
    for (const text of some) expect([text, destructive(text) !== undefined]).toEqual([text, true]);
  });
  it("leaves work in a project and in temporary folders alone", () => {
    for (const text of none) expect([text, destructive(text)]).toEqual([text, undefined]);
  });
});
