<?php
// Re-triage A5-A7: helper names are not SQL escaping (helpers defined in the same file are followed).
function unsafe_raw($v) { return trim($v); }
function clean_input($v) { return trim($v); }
function a5($db) {
  $v = unsafe_raw($_GET['q']);
  return $db->query("SELECT * FROM t WHERE a = '" . $v . "'");
}
function a6($db, $e) {
  $v = $e->escapeHtml($_GET['q']);
  return $db->query("SELECT * FROM t WHERE a = '" . $v . "'");
}
function a7($db) {
  $v = clean_input($_GET['q']);
  return $db->query("SELECT * FROM t WHERE a = '" . $v . "'");
}
function a8($wpdb) {
  return $wpdb->query(sprintf("DELETE FROM t WHERE slug = '%s'", $_GET['slug']));
}
