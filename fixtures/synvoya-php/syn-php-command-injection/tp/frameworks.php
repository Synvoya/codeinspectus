<?php
class Tools {
    public function run(Request $request) {
        $process = Process::fromShellCommandline('git log ' . $request->input('ref'));
        $process->run();
        return Illuminate\Support\Facades\Process::run('du -sh ' . $request->input('path'));
    }
}
