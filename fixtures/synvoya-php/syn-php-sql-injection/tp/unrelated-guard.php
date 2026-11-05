<?php
// Re-triage 2: an allow-list check on a different variable does not protect the query.
function t4($db, $status) {
  if (in_array($status, ['open', 'closed'], true)) { $status = 'open'; }
  return $db->query("SELECT * FROM t WHERE id = " . $_GET['id']);
}
function t5($wpdb) {
  $type = $_GET['type'];
  if (!in_array($type, ['a', 'b'], true)) { return; }
  $wpdb->query("DELETE FROM t WHERE owner = '" . $_POST['owner'] . "' AND type = '$type'");
}
