<?php
system("ping -c 1 " . escapeshellarg($_GET['host']));
$n = (int) $_GET['n'];
shell_exec("seq " . $n);
proc_open(['ping', '-c', '1', $_GET['host']], [], $pipes);
class Tools {
    public function run(Request $request) {
        return Process::run(['git', 'log', $request->input('ref')]);
    }
}
$pdo->exec("VACUUM");
$listing = `ls -la`;
