<?php
// SQL and HTML escapers, and path cleaners, do not make a value safe for a shell.
function c1($conn) {
  $host = $conn->real_escape_string($_GET['host']);
  system("ping -c 1 " . $host);
}
function c2() {
  $name = htmlspecialchars($_POST['name']);
  shell_exec("convert " . $name . " out.png");
}
function fm_clean_path($path) {
  return str_replace(array('../', '..\\'), '', trim($path, '\\/'));
}
function c3() {
  $path = fm_clean_path($_GET['p']);
  passthru("stat -c%s \"$path\"");
}
